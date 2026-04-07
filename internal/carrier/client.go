package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"github.com/houden/mirage/internal/morph"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	DataBudget     = 2 * 1024 * 1024 // 2MB per downstream connection
	UpstreamBudget = 256 * 1024      // 256KB per POST

	connLifetimeMin = 60
	connLifetimeMax = 180
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
	morpher   *morph.Morpher
	startTime time.Time
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
		morpher:   morph.New(10.0), // tau=10s exponential decay
		startTime: time.Now(),
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

func (c *ClientCarrier) streamAge() time.Duration {
	return time.Since(c.startTime)
}

// maybePad appends random padding bytes to data based on morphing probability.
// Early in session: high probability, large padding. Later: decays to zero.
func (c *ClientCarrier) maybePad(data []byte) []byte {
	if !c.morpher.ShouldPad(c.streamAge()) {
		return data
	}
	padSize := c.morpher.PadSize()
	if padSize > 4096 {
		padSize = 4096 // cap padding to avoid excessive overhead
	}
	padding := make([]byte, padSize)
	rand.Read(padding)
	// Append as a "padding packet" with length prefix (server ignores unknown data after valid packets)
	padPkt := encodePacket(padding)
	return append(data, padPkt...)
}

func (c *ClientCarrier) upstreamLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case pkt := <-c.outbound:
			buf := encodePacket(pkt)
		drain:
			for {
				select {
				case extra := <-c.outbound:
					encoded := encodePacket(extra)
					if len(buf)+len(encoded) > UpstreamBudget {
						payload := c.maybePad(buf)
						if err := c.sendUpstream(payload); err != nil {
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

			// Apply morphing: maybe add padding + inter-packet delay
			payload := c.maybePad(buf)
			if delay := c.morpher.InterPacketDelay(c.streamAge()); delay > 0 {
				time.Sleep(delay)
			}

			if err := c.sendUpstream(payload); err != nil {
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
	lifetime := time.Duration(connLifetimeMin+mrand.Intn(connLifetimeMax-connLifetimeMin+1)) * time.Second
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
		totalBytes += int64(pktLen) + 2
		c.deliver(pkt)

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
