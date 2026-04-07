package carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/houden/mirage/internal/auth"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	DataBudget      = 2 * 1024 * 1024
	connLifetimeMin = 60
	connLifetimeMax = 180
	// Batch multiple QUIC packets per POST for efficiency.
	// Wait up to this long to collect more packets before sending.
	batchWait = 2 * time.Millisecond
)

type ClientCarrier struct {
	serverURL string
	auth      *auth.Auth
	sessionID []byte
	client    *http.Client
	outbound  <-chan []byte
	deliver   func(data []byte)
	ctx       context.Context
	cancel    context.CancelFunc
}

type ClientCarrierConfig struct {
	ServerAddr string
	Auth       *auth.Auth
	SessionID  []byte
	Outbound   <-chan []byte
	Deliver    func(data []byte)
}

func NewClientCarrier(cfg ClientCarrierConfig) *ClientCarrier {
	ctx, cancel := context.WithCancel(context.Background())

	h2tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tlsConn := utls.UClient(conn, &utls.Config{
				ServerName: host,
				NextProtos: []string{"h2"},
			}, utls.HelloChrome_Auto)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		DisableCompression: true,
	}

	return &ClientCarrier{
		serverURL: "https://" + cfg.ServerAddr,
		auth:      cfg.Auth,
		sessionID: cfg.SessionID,
		client:    &http.Client{Transport: h2tr},
		outbound:  cfg.Outbound,
		deliver:   cfg.Deliver,
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (c *ClientCarrier) Run() {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.upstreamLoop() }()
	go func() { defer wg.Done(); c.downstreamLoop() }()
	wg.Wait()
}

func (c *ClientCarrier) Stop() { c.cancel() }

func (c *ClientCarrier) freshToken() string {
	token, err := c.auth.Generate(1, c.sessionID)
	if err != nil {
		log.Printf("carrier: generate token: %v", err)
		return ""
	}
	return token
}

// upstreamLoop sends QUIC packets via HTTP POST.
// Uses batching with a short delay to collect multiple packets per POST,
// dramatically reducing HTTP round-trip overhead while keeping latency low.
func (c *ClientCarrier) upstreamLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case pkt := <-c.outbound:
			buf := encodePacket(pkt)
			// Short wait to batch more packets
			timer := time.NewTimer(batchWait)
		drain:
			for {
				select {
				case extra := <-c.outbound:
					buf = append(buf, encodePacket(extra)...)
					if len(buf) > 32*1024 { // flush at 32KB
						break drain
					}
				case <-timer.C:
					break drain
				case <-c.ctx.Done():
					timer.Stop()
					return
				}
			}
			timer.Stop()

			if err := c.sendUpstream(buf); err != nil {
				log.Printf("carrier up: %v", err)
				time.Sleep(200 * time.Millisecond)
			}
		}
	}
}

func (c *ClientCarrier) sendUpstream(data []byte) error {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost,
		c.serverURL+"/api/v2/upload", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.freshToken())
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func (c *ClientCarrier) downstreamLoop() {
	for {
		if c.ctx.Err() != nil {
			return
		}
		if err := c.openDownstream(); err != nil {
			log.Printf("carrier down: %v", err)
			time.Sleep(300 * time.Millisecond)
		}
	}
}

func (c *ClientCarrier) openDownstream() error {
	lifetime := time.Duration(connLifetimeMin+mrand.Intn(connLifetimeMax-connLifetimeMin+1)) * time.Second
	connCtx, connCancel := context.WithTimeout(c.ctx, lifetime)
	defer connCancel()

	req, err := http.NewRequestWithContext(connCtx, http.MethodGet,
		c.serverURL+"/api/v2/stream", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.freshToken())

	resp, err := c.client.Do(req)
	if err != nil {
		if c.ctx.Err() == nil && connCtx.Err() != nil {
			return nil
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	start := time.Now()
	var totalBytes int64

	for {
		var pktLen uint16
		if err := binary.Read(resp.Body, binary.BigEndian, &pktLen); err != nil {
			if connCtx.Err() != nil && c.ctx.Err() == nil {
				log.Printf("carrier: rotating downstream (bytes=%d, age=%s)",
					totalBytes, time.Since(start).Round(time.Millisecond))
				return nil
			}
			return err
		}
		pkt := make([]byte, pktLen)
		if _, err := io.ReadFull(resp.Body, pkt); err != nil {
			if connCtx.Err() != nil && c.ctx.Err() == nil {
				log.Printf("carrier: rotating downstream (bytes=%d, age=%s)",
					totalBytes, time.Since(start).Round(time.Millisecond))
				return nil
			}
			return err
		}
		totalBytes += int64(pktLen) + 2
		c.deliver(pkt)

		if totalBytes >= DataBudget {
			log.Printf("carrier: rotating downstream (bytes=%d, age=%s)",
				totalBytes, time.Since(start).Round(time.Millisecond))
			return nil
		}
	}
}

func encodePacket(pkt []byte) []byte {
	buf := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(pkt)))
	copy(buf[2:], pkt)
	return buf
}
