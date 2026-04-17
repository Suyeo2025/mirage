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
	"strconv"
	"sync"
	"sync/atomic"
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

	// resetErrorThreshold is how many consecutive errors we tolerate before
	// rebuilding the HTTP/2 transport. Set high enough that a brief server
	// hiccup (e.g. restart, 401 during clock skew) does not cascade into a
	// storm of resets — each reset cancels all in-flight requests, so they
	// should be infrequent. (Byte-level ACK now makes a reset non-lossy, but
	// it still wastes a roundtrip.)
	resetErrorThreshold = 10
)

// Wire headers for byte-level ACK. Server and client are shipped together
// from the same build, so there is no version negotiation — both sides
// assume the peer speaks the same dialect.
const (
	headerMirageOffset = "X-Mirage-Offset" // POST body's absolute upstream start offset
	headerMirageRx     = "X-Mirage-Rx"     // bytes-received-so-far ack
)

type ClientCarrier struct {
	serverURL   string
	auth        *auth.Auth
	sessionID   []byte
	userID      uint16
	client      *http.Client
	upstream    *mux.ReplayPipe // mux writes frames here; Snapshot()/Ack() on retry
	downstreamW io.Writer       // carrier writes here ← GET response → mux reads
	ctx         context.Context
	cancel      context.CancelFunc
	buildDialTLS func() func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error)
	mu           sync.Mutex

	// Epoch context: every in-flight POST/GET derives from epochCtx. On
	// resetTransport we cancel the old epoch and create a new one, which
	// forces all pending requests on the stale transport to abort
	// synchronously (instead of drifting for up to 5 minutes until their
	// own timeouts fire and leaking orphan TCP conns in the meantime).
	epochMu     sync.Mutex
	epochCtx    context.Context
	epochCancel context.CancelFunc

	// Byte-level ACK state (protocol v2):
	//   upAckedOff  — highest upstream byte server has confirmed receiving.
	//                 POST body always starts here; successful response bumps it.
	//   downRxOff   — total downstream bytes received from server. Sent back on
	//                 every request so server can trim its downstream replay
	//                 and resume a reset GET from exactly where this client
	//                 stopped reading.
	upAckedOff atomic.Uint64
	downRxOff  atomic.Uint64
}

type ClientCarrierConfig struct {
	ServerAddr  string
	Auth        *auth.Auth
	SessionID   []byte
	UserID      uint16
	Upstream    *mux.ReplayPipe // mux session writes frames here
	DownstreamW io.Writer       // carrier writes received frames here

	// REALITY config (optional). When PublicKey is set, uses reality.Client().
	RealityPublicKey string // x25519 public key (base64)
	RealityShortID   string // short ID (hex)
	RealitySNI       string // server name (e.g. "troncent.com")
}

func NewClientCarrier(cfg ClientCarrierConfig) *ClientCarrier {
	ctx, cancel := context.WithCancel(context.Background())

	buildDialer := func() func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		return buildTLSDialer(cfg)
	}

	h2tr := &http2.Transport{
		DialTLSContext:     buildDialer(),
		DisableCompression: true,
		ReadIdleTimeout:    15 * time.Second, // send PING after 15s idle
		PingTimeout:        5 * time.Second,  // close conn if no PONG in 5s
	}

	userID := cfg.UserID
	if userID == 0 {
		userID = 1
	}
	serverURL := "https://" + cfg.ServerAddr
	if cfg.RealitySNI != "" {
		_, port, _ := net.SplitHostPort(cfg.ServerAddr)
		if port != "" {
			serverURL = "https://" + cfg.RealitySNI + ":" + port
		} else {
			serverURL = "https://" + cfg.RealitySNI
		}
	}
	cc := &ClientCarrier{
		serverURL:    serverURL,
		auth:         cfg.Auth,
		sessionID:    cfg.SessionID,
		userID:       userID,
		client:       &http.Client{Transport: h2tr},
		upstream:     cfg.Upstream,
		downstreamW:  cfg.DownstreamW,
		ctx:          ctx,
		cancel:       cancel,
		buildDialTLS: buildDialer,
	}
	cc.epochCtx, cc.epochCancel = context.WithCancel(ctx)
	return cc
}

// currentEpoch returns the parent context for any new POST/GET. When the
// caller's request errors, it should compare its ctx with a fresh epoch
// call to decide whether an error was a reset-triggered cancel or a real
// failure.
func (c *ClientCarrier) currentEpoch() context.Context {
	c.epochMu.Lock()
	defer c.epochMu.Unlock()
	return c.epochCtx
}

// resetTransport cancels all in-flight requests on the current transport,
// swaps in a fresh transport, and asynchronously reaps the old one's idle
// connections. The cancel step is critical: without it, the old transport's
// in-flight POST/GET keeps a TCP conn alive until the request's own timeout
// (up to 5 minutes for a long-lived GET), which is how the client
// previously ended up with 200+ orphan sockets after a brief 401 storm.
func (c *ClientCarrier) resetTransport() {
	c.mu.Lock()
	defer c.mu.Unlock()
	log.Printf("carrier: resetting HTTP/2 transport")

	// 1. Abort everything derived from the current epoch. Pending requests
	//    see ctx.Canceled, return immediately, release their streams, and
	//    the old TCP conns become genuinely idle.
	c.epochMu.Lock()
	if c.epochCancel != nil {
		c.epochCancel()
	}
	c.epochCtx, c.epochCancel = context.WithCancel(c.ctx)
	c.epochMu.Unlock()

	// 2. Swap in a fresh transport for future requests.
	oldTr, _ := c.client.Transport.(*http2.Transport)
	c.client.Transport = &http2.Transport{
		DialTLSContext:     c.buildDialTLS(),
		DisableCompression: true,
		ReadIdleTimeout:    15 * time.Second,
		PingTimeout:        5 * time.Second,
	}

	// 3. Reap the old transport's conns. CloseIdleConnections is a no-op
	//    against conns that still hold in-flight streams; we call it twice
	//    (immediately + after a short grace) so conns freshly released by
	//    step 1 are caught on the second pass.
	if oldTr != nil {
		go func(tr *http2.Transport) {
			tr.CloseIdleConnections()
			time.Sleep(3 * time.Second)
			tr.CloseIdleConnections()
		}(oldTr)
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
			dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
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
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
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

func (c *ClientCarrier) Stop() {
	c.epochMu.Lock()
	if c.epochCancel != nil {
		c.epochCancel()
	}
	c.epochMu.Unlock()
	c.cancel()
}

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

	var consecutiveErrors int

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-flush.C:
			// Snapshot all unacked bytes since last server-ack'd offset.
			// Byte-level retransmit: the POST body always starts at the last
			// acknowledged offset. The server dedupes any overlap using the
			// X-Mirage-Offset header, so a failed POST can be retried
			// without the data-loss / double-delivery risks of a destructive
			// drain.
			off := c.upAckedOff.Load()
			data := c.upstream.Snapshot(off)
			if len(data) == 0 {
				continue
			}
			if err := c.sendPost(data, off); err != nil {
				consecutiveErrors++
				log.Printf("carrier up: %v (errors=%d)", err, consecutiveErrors)
				if consecutiveErrors >= resetErrorThreshold {
					c.resetTransport()
					consecutiveErrors = 0
				}
				time.Sleep(backoffDelay(consecutiveErrors))
			} else {
				consecutiveErrors = 0
			}
			keepalive.Reset(keepaliveInterval())
		case <-keepalive.C:
			// Idle keepalive doubles as an ACK carrier: by sending even with
			// no data we feed the server an up-to-date X-Mirage-Rx so it can
			// trim its downstream replay buffer.
			if err := c.sendPost(nil, c.upAckedOff.Load()); err != nil {
				consecutiveErrors++
				if consecutiveErrors >= resetErrorThreshold {
					c.resetTransport()
					consecutiveErrors = 0
				}
			} else {
				consecutiveErrors = 0
			}
			keepalive.Reset(keepaliveInterval())
		}
	}
}

// backoffDelay returns an exponential backoff capped at ~3s. Prevents a tight
// retry loop during a prolonged outage from burning CPU and log volume.
func backoffDelay(errCount int) time.Duration {
	if errCount < 1 {
		return 0
	}
	// 200ms, 400ms, 800ms, 1.6s, 3s, 3s, ...
	d := time.Duration(200) * time.Millisecond
	for i := 1; i < errCount && d < 3*time.Second; i++ {
		d *= 2
	}
	if d > 3*time.Second {
		d = 3 * time.Second
	}
	return d
}

// sendPost delivers one POST that starts at absolute upstream byte offset
// `off`. On 2xx it reads the server's acknowledged-receive offset out of the
// X-Mirage-Rx response header, advances upAckedOff, and trims the replay
// buffer. On error nothing is advanced — next tick retries the same range
// (plus any new bytes written in the meantime).
func (c *ClientCarrier) sendPost(data []byte, off uint64) error {
	// Parent the request context on the current epoch so a concurrent
	// resetTransport call (triggered from downstreamLoop) aborts us instead
	// of leaving the POST hanging on a stale conn.
	postCtx, cancel := context.WithTimeout(c.currentEpoch(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(postCtx, http.MethodPost,
		c.serverURL+"/api/v2/tunnel", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.freshToken())
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(headerMirageOffset, strconv.FormatUint(off, 10))
	req.Header.Set(headerMirageRx, strconv.FormatUint(c.downRxOff.Load(), 10))

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	// Parse the server's receive offset and trim our replay buffer.
	if rxHdr := resp.Header.Get(headerMirageRx); rxHdr != "" {
		if newAck, perr := strconv.ParseUint(rxHdr, 10, 64); perr == nil {
			// Monotonic: never go backwards.
			for {
				cur := c.upAckedOff.Load()
				if newAck <= cur {
					break
				}
				if c.upAckedOff.CompareAndSwap(cur, newAck) {
					c.upstream.Ack(newAck)
					break
				}
			}
		}
	}
	return nil
}

// downstreamLoop: persistent GET, streams response to downstreamW.
func (c *ClientCarrier) downstreamLoop() {
	var consecutiveErrors int
	for {
		if c.ctx.Err() != nil {
			return
		}
		if err := c.openGet(); err != nil {
			consecutiveErrors++
			log.Printf("carrier down: %v (errors=%d)", err, consecutiveErrors)
			if consecutiveErrors >= resetErrorThreshold {
				c.resetTransport()
				consecutiveErrors = 0
			}
			time.Sleep(backoffDelay(consecutiveErrors))
		} else {
			consecutiveErrors = 0
		}
	}
}

func (c *ClientCarrier) openGet() error {
	// Same rationale as sendPost: parent on the current epoch so reset
	// tears the long-lived GET down synchronously instead of orphaning it.
	lifetime := time.Duration(connLifetimeMin+mrand.Intn(connLifetimeMax-connLifetimeMin+1)) * time.Second
	connCtx, connCancel := context.WithTimeout(c.currentEpoch(), lifetime)
	defer connCancel()

	req, err := http.NewRequestWithContext(connCtx, http.MethodGet,
		c.serverURL+"/api/v2/tunnel", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.freshToken())
	// Tell server where to resume: any downstream bytes past this offset
	// that are still in the server's replay buffer will be re-sent to us.
	// This is what eliminates desync across GET rotations.
	req.Header.Set(headerMirageRx, strconv.FormatUint(c.downRxOff.Load(), 10))

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

	// Force-close resp.Body when context expires, unblocking io.Copy.
	go func() {
		<-connCtx.Done()
		resp.Body.Close()
	}()

	// Stream response body to mux downstream, counting bytes for the
	// downstream ACK reported back on the next POST / GET.
	start := time.Now()
	n, _ := io.Copy(&downstreamCounter{w: c.downstreamW, carrier: c}, resp.Body)
	if connCtx.Err() != nil && c.ctx.Err() == nil {
		log.Printf("carrier: rotating downstream (bytes=%d, age=%s)",
			n, time.Since(start).Round(time.Millisecond))
	}
	return nil
}

// downstreamCounter is an io.Writer that forwards to the mux downstream
// pipe while advancing the carrier's downRxOff counter. We count *at the
// application layer* (what made it into the mux's input) rather than the
// kernel's TCP recv — this is the offset the server can safely trim to.
type downstreamCounter struct {
	w       io.Writer
	carrier *ClientCarrier
}

func (d *downstreamCounter) Write(p []byte) (int, error) {
	n, err := d.w.Write(p)
	if n > 0 {
		d.carrier.downRxOff.Add(uint64(n))
	}
	return n, err
}
