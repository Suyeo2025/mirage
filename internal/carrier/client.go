package carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/houden/mirage/internal/auth"
	"github.com/houden/mirage/internal/mux"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	connLifetimeMin = 120
	connLifetimeMax = 300
	batchWait       = 3 * time.Millisecond // short wait to batch upstream frames
)

type ClientCarrier struct {
	serverURL   string
	auth        *auth.Auth
	sessionID   []byte
	client      *http.Client
	upstream    *mux.BufPipe   // mux writes here → carrier reads → POST
	downstreamW *io.PipeWriter // carrier writes here ← GET response → mux reads
	ctx         context.Context
	cancel      context.CancelFunc
}

type ClientCarrierConfig struct {
	ServerAddr  string
	Auth        *auth.Auth
	SessionID   []byte
	Upstream    *mux.BufPipe   // mux session writes frames here
	DownstreamW *io.PipeWriter // carrier writes received frames here
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
		serverURL:   "https://" + cfg.ServerAddr,
		auth:        cfg.Auth,
		sessionID:   cfg.SessionID,
		client:      &http.Client{Transport: h2tr},
		upstream:    cfg.Upstream,
		downstreamW: cfg.DownstreamW,
		ctx:         ctx,
		cancel:      cancel,
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
	t, _ := c.auth.Generate(1, c.sessionID)
	return t
}

// upstreamLoop: drain buffered mux frames from BufPipe, send as POST batches.
// BufPipe never blocks on write, so mux is never stalled.
func (c *ClientCarrier) upstreamLoop() {
	for {
		if c.ctx.Err() != nil {
			return
		}
		// Block until data is available
		data, err := c.upstream.WaitAndDrain()
		if err != nil {
			return
		}
		// Short wait to batch more
		time.Sleep(batchWait)
		if extra := c.upstream.Drain(); len(extra) > 0 {
			data = append(data, extra...)
		}

		if err := c.sendPost(data); err != nil {
			log.Printf("carrier up: %v", err)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func (c *ClientCarrier) sendPost(data []byte) error {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost,
		c.serverURL+"/api/v2/tunnel", bytes.NewReader(data))
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

// downstreamLoop: persistent GET, streams response to downstreamW.
func (c *ClientCarrier) downstreamLoop() {
	for {
		if c.ctx.Err() != nil {
			return
		}
		if err := c.openGet(); err != nil {
			log.Printf("carrier down: %v", err)
			time.Sleep(300 * time.Millisecond)
		}
	}
}

func (c *ClientCarrier) openGet() error {
	lifetime := time.Duration(connLifetimeMin+mrand.Intn(connLifetimeMax-connLifetimeMin+1)) * time.Second
	connCtx, connCancel := context.WithTimeout(c.ctx, lifetime)
	defer connCancel()

	req, err := http.NewRequestWithContext(connCtx, http.MethodGet,
		c.serverURL+"/api/v2/tunnel", nil)
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

	// Stream response body directly to mux downstream
	start := time.Now()
	n, _ := io.Copy(c.downstreamW, resp.Body)
	if connCtx.Err() != nil && c.ctx.Err() == nil {
		log.Printf("carrier: rotating downstream (bytes=%d, age=%s)",
			n, time.Since(start).Round(time.Millisecond))
	}
	return nil
}
