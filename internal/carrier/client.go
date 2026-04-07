package carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/houden/mirage/internal/auth"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	// DataBudget is the maximum bytes received on a single downstream
	// connection before rotating it. Defeats TSPU freezing at ~15-20KB.
	DataBudget = 12 * 1024

	// UpstreamBudget is the maximum payload size for a single POST.
	UpstreamBudget = 12 * 1024

	// connLifetimeMin and connLifetimeMax define the random lifetime
	// window for a downstream connection (seconds).
	connLifetimeMin = 30
	connLifetimeMax = 60
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

	// Use http2.Transport directly with uTLS DialTLSContext.
	// Go's http.Transport + DialTLSContext doesn't properly detect h2,
	// causing "HTTP/1.x transport connection broken" errors.
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

func (c *ClientCarrier) upstreamLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case pkt := <-c.outbound:
			buf := encodePacket(pkt)
			// Drain the channel, but respect the per-POST budget.
		drain:
			for {
				select {
				case extra := <-c.outbound:
					encoded := encodePacket(extra)
					if len(buf)+len(encoded) > UpstreamBudget {
						// Current batch is full; send it, then
						// start a new batch with this packet.
						if err := c.sendUpstream(buf); err != nil {
							log.Printf("carrier up: %v", err)
							time.Sleep(200 * time.Millisecond)
						}
						buf = encoded
					} else {
						buf = append(buf, encoded...)
					}
				default:
					break drain
				}
			}
			if err := c.sendUpstream(buf); err != nil {
				log.Printf("carrier up: %v", err)
				time.Sleep(200 * time.Millisecond)
			}
		}
	}
}

func (c *ClientCarrier) downstreamLoop() {
	for {
		if c.ctx.Err() != nil {
			return
		}
		if err := c.openDownstream(); err != nil {
			log.Printf("carrier down: %v", err)
			time.Sleep(500 * time.Millisecond)
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

func (c *ClientCarrier) openDownstream() error {
	// Pick a random lifetime for this connection (30-60s).
	lifetime := time.Duration(connLifetimeMin+rand.Intn(connLifetimeMax-connLifetimeMin+1)) * time.Second
	deadline := time.Now().Add(lifetime)

	connCtx, connCancel := context.WithDeadline(c.ctx, deadline)
	defer connCancel()

	req, err := http.NewRequestWithContext(connCtx, http.MethodGet,
		c.serverURL+"/api/v2/stream", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.freshToken())

	resp, err := c.client.Do(req)
	if err != nil {
		// If the parent context is fine but our deadline fired, this is
		// a normal rotation -- not an error worth propagating.
		if c.ctx.Err() == nil && connCtx.Err() != nil {
			log.Printf("carrier: rotating downstream (bytes=0, age=%s)", lifetime)
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
			// Context deadline means we hit the lifetime cap.
			if connCtx.Err() != nil && c.ctx.Err() == nil {
				log.Printf("carrier: rotating downstream (bytes=%d, age=%s)", totalBytes, time.Since(start).Round(time.Millisecond))
				return nil
			}
			return err
		}
		pkt := make([]byte, pktLen)
		if _, err := io.ReadFull(resp.Body, pkt); err != nil {
			if connCtx.Err() != nil && c.ctx.Err() == nil {
				log.Printf("carrier: rotating downstream (bytes=%d, age=%s)", totalBytes, time.Since(start).Round(time.Millisecond))
				return nil
			}
			return err
		}
		totalBytes += int64(pktLen) + 2 // include the 2-byte length header
		c.deliver(pkt)

		// Data budget exceeded -- rotate.
		if totalBytes >= DataBudget {
			log.Printf("carrier: rotating downstream (bytes=%d, age=%s)", totalBytes, time.Since(start).Round(time.Millisecond))
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
