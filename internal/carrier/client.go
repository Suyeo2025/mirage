package carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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

	// RTT defense: fixed-interval flush quantizes observable RTT into discrete steps.
	// Xue et al. (NDSS 2025) dMAP classifier exploits continuous RTT measurement.
	// By flushing at fixed intervals, RTT is quantized to multiples of flushInterval,
	// making precise RTT estimation unreliable.
	flushInterval = 50 * time.Millisecond // 50ms quantization step
)

type ClientCarrier struct {
	serverURL   string
	auth        *auth.Auth
	sessionID   []byte
	userID      uint16
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
	UserID      uint16
	Upstream    *mux.BufPipe   // mux session writes frames here
	DownstreamW *io.PipeWriter // carrier writes received frames here

	// REALITY config (optional). When PublicKey is set, uses reality.Client().
	RealityPublicKey string // x25519 public key (base64)
	RealityShortID   string // short ID (hex)
	RealitySNI       string // server name (e.g. "troncent.com")
}

func NewClientCarrier(cfg ClientCarrierConfig) *ClientCarrier {
	ctx, cancel := context.WithCancel(context.Background())

	dialTLS := buildTLSDialer(cfg)

	h2tr := &http2.Transport{
		DialTLSContext: dialTLS,
		DisableCompression: true,
	}

	userID := cfg.UserID
	if userID == 0 {
		userID = 1
	}
	// When RealitySNI is set and ServerAddr is an IP, use SNI as the URL hostname
	// so TLS certificate validation uses the domain name, while DialTLS connects
	// to the actual IP (handled by buildTLSDialer).
	serverURL := "https://" + cfg.ServerAddr
	if cfg.RealitySNI != "" {
		_, port, _ := net.SplitHostPort(cfg.ServerAddr)
		if port != "" {
			serverURL = "https://" + cfg.RealitySNI + ":" + port
		} else {
			serverURL = "https://" + cfg.RealitySNI
		}
	}
	return &ClientCarrier{
		serverURL:   serverURL,
		auth:        cfg.Auth,
		sessionID:   cfg.SessionID,
		userID:      userID,
		client:      &http.Client{Transport: h2tr},
		upstream:    cfg.Upstream,
		downstreamW: cfg.DownstreamW,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// buildTLSDialer returns a TLS dial function.
// If REALITY is configured, uses reality.Client() for perfect TLS mimicry.
// Otherwise, uses uTLS with Chrome fingerprint.
func buildTLSDialer(cfg ClientCarrierConfig) func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	if cfg.RealityPublicKey != "" {
		pubKey, _ := base64.RawURLEncoding.DecodeString(cfg.RealityPublicKey)
		shortIDBytes, _ := hex.DecodeString(cfg.RealityShortID)
		var shortID [8]byte
		copy(shortID[:], shortIDBytes)
		realDialAddr := cfg.ServerAddr // real IP:port

		return func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			// Always dial the real server IP, not the SNI domain from URL
			host, _, _ := net.SplitHostPort(addr)
			dialTarget := addr
			if cfg.RealitySNI != "" && host == cfg.RealitySNI {
				dialTarget = realDialAddr
			}
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			conn, err := dialer.DialContext(ctx, network, dialTarget)
			if err != nil {
				return nil, err
			}
			sni := cfg.RealitySNI
			if sni == "" {
				sni, _, _ = net.SplitHostPort(addr)
			}
			return realityDial(ctx, conn, pubKey, shortID, sni)
		}
	}

	// Default: uTLS Chrome fingerprint
	// When RealitySNI is set but no REALITY PublicKey, use SNI override but regular uTLS.
	// Also resolve the actual dial address if the URL uses the SNI domain.
	dialAddr := cfg.ServerAddr // real IP:port to dial
	return func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		// If addr is the SNI domain (from URL), replace with real server address
		actualAddr := addr
		if cfg.RealitySNI != "" && host == cfg.RealitySNI {
			actualAddr = dialAddr
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := dialer.DialContext(ctx, network, actualAddr)
		if err != nil {
			return nil, err
		}
		sni := host
		if cfg.RealitySNI != "" {
			sni = cfg.RealitySNI
		}
		tlsConn := utls.UClient(conn, &utls.Config{
			ServerName: sni,
			NextProtos: []string{"h2"},
		}, utls.HelloChrome_Auto)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
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
	t, err := c.auth.Generate(c.userID, c.sessionID)
	if err != nil {
		log.Printf("carrier: token generation failed: %v", err)
	}
	return t
}

// upstreamLoop: fixed-interval flush with RTT quantization.
//
// Defense against cross-layer RTT fingerprinting (Xue et al., NDSS 2025):
// Instead of sending data immediately when available (which exposes precise
// application-layer RTT), we accumulate data and flush at fixed intervals.
// This quantizes the observable RTT to multiples of flushInterval (50ms),
// making the dMAP classifier's RTT estimation unreliable.
//
// Additionally, keepalive sends during idle periods maintain a constant
// stream of POST requests, preventing idle-pattern analysis.
func (c *ClientCarrier) upstreamLoop() {
	flush := time.NewTicker(flushInterval)
	defer flush.Stop()

	keepaliveInterval := func() time.Duration {
		return time.Duration(3000+mrand.Intn(5000)) * time.Millisecond
	}
	keepalive := time.NewTimer(keepaliveInterval())
	defer keepalive.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-flush.C:
			// Fixed-interval flush: drain all buffered data and send
			data := c.upstream.Drain()
			if len(data) == 0 {
				continue
			}
			if err := c.sendPost(data); err != nil {
				log.Printf("carrier up: %v", err)
				time.Sleep(200 * time.Millisecond)
			}
			keepalive.Reset(keepaliveInterval())
		case <-keepalive.C:
			// Idle keepalive
			c.sendPost(nil)
			keepalive.Reset(keepaliveInterval())
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
