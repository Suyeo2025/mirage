package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/houden/mirage/internal/auth"
	"github.com/houden/mirage/internal/morph"
	"github.com/houden/mirage/internal/mux"
	"github.com/houden/mirage/internal/outbound"
	"github.com/houden/mirage/internal/relay"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	reality "github.com/xtls/reality"
)

// Wire headers for byte-level ACK. Must match the client's carrier package.
// Server and client ship together from the same build, so no version gate.
const (
	headerMirageOffset = "X-Mirage-Offset"
	headerMirageRx     = "X-Mirage-Rx"
)

type Config struct {
	Domain        string
	PSK           string
	WebRoot       string
	CertDir       string
	CertFile      string // path to TLS cert (optional, skips autocert)
	KeyFile       string // path to TLS key (optional, skips autocert)
	NoTLS         bool   // plain HTTP mode (for use behind REALITY/nginx)
	Listen        string
	PaddingConfig string // path to padding config JSON file (optional)
	Verbose       bool   // if true, log target addresses

	// REALITY config (optional — enables REALITY TLS when set)
	RealityDest       string // handshake target, e.g. "troncent.com:443"
	RealityServerName string // SNI for REALITY, e.g. "troncent.com"
	RealityPrivateKey string // x25519 private key (base64)
	RealityShortID    string // short ID (hex)

	// Outbound proxy (optional — routes proxied traffic through an upstream proxy)
	Outbound outbound.Dialer
}

type serverSession struct {
	sess       *mux.Session
	downstream *mux.ReplayPipe // mux writes downstream frames here → GET reads at offset
	upstreamW  io.Writer       // POST body data written here → mux RecvLoop reads
	upstreamPW *io.PipeWriter  // kept for Close() to unblock RecvLoop goroutine
	lastActive atomic.Int64    // unix timestamp of last activity

	// Byte-level ACK state (protocol v2):
	//   upRecv — total POST bytes this session has accepted and forwarded to
	//            upstreamW. Clients include their X-Mirage-Offset on each
	//            POST; server dedupes any overlap using upRecv and responds
	//            with X-Mirage-Rx: upRecv.
	upRecv atomic.Uint64

	stopDecoys func() // cancel decoy generator on teardown

	// downCancelMu guards the currently-serving GET handler's cancel func.
	// Only one downstream handler may own the ReplayPipe at a time: a new
	// GET arriving for this session cancels the previous one so data is
	// never split between two response bodies (which would desync the
	// client's mux RecvLoop).
	//
	// Identity is tracked via a monotonic generation counter rather than
	// CancelFunc pointer comparison (which is not reliable — all closures
	// from context.WithCancel share the same code pointer).
	downCancelMu sync.Mutex
	downCancel   context.CancelFunc
	downGen      uint64
}

func (ss *serverSession) touch() {
	ss.lastActive.Store(time.Now().Unix())
}

// installDownHandler registers cancel as the current downstream handler's
// cancel func, invokes the previous one (if any) to kick the old handler
// out of its WaitAndDrainCtx loop, and returns a generation token the
// caller must pass to releaseDownHandler.
func (ss *serverSession) installDownHandler(cancel context.CancelFunc) uint64 {
	ss.downCancelMu.Lock()
	old := ss.downCancel
	ss.downGen++
	gen := ss.downGen
	ss.downCancel = cancel
	ss.downCancelMu.Unlock()
	if old != nil {
		old()
	}
	return gen
}

// releaseDownHandler clears the registered cancel iff the caller's generation
// still matches. A superseded handler's gen is stale and leaves the slot
// untouched so the successor's cancel remains reachable.
func (ss *serverSession) releaseDownHandler(gen uint64) {
	ss.downCancelMu.Lock()
	defer ss.downCancelMu.Unlock()
	if ss.downGen == gen {
		ss.downCancel = nil
	}
}

// cancelDownHandler cancels and clears the current downstream handler, if any.
// Called during session teardown.
func (ss *serverSession) cancelDownHandler() {
	ss.downCancelMu.Lock()
	c := ss.downCancel
	ss.downCancel = nil
	ss.downCancelMu.Unlock()
	if c != nil {
		c()
	}
}

type Server struct {
	config     Config
	auth       *auth.Auth
	mu         sync.Mutex
	sessions   map[string]*serverSession
	paddingCfg atomic.Pointer[mux.PaddingConfig]
	morpher    *morph.Morpher
}

func New(cfg Config) *Server {
	s := &Server{
		config:   cfg,
		auth:     auth.New(cfg.PSK),
		sessions: make(map[string]*serverSession),
	}

	// Initialize padding config
	padCfg := mux.DefaultPaddingConfig()
	if cfg.PaddingConfig != "" {
		if loaded, err := loadPaddingConfigJSON(cfg.PaddingConfig); err == nil {
			padCfg = loaded
			log.Printf("loaded padding config from %s", cfg.PaddingConfig)
		} else {
			log.Printf("padding config load failed, using defaults: %v", err)
		}
	}
	s.paddingCfg.Store(padCfg)

	// Create morpher from padding config
	s.morpher = morph.New(paddingToMorphConfig(padCfg))

	return s
}

func (s *Server) Run(ctx context.Context) error {
	m := http.NewServeMux()
	m.HandleFunc("/api/v2/tunnel", s.handleTunnel)
	m.HandleFunc("/api/v1/sync", s.handleTunnel)
	m.HandleFunc("/api/v1/courses/stream", s.handleTunnel)
	m.HandleFunc("/", s.serveWebsite)

	srv := &http.Server{Addr: s.config.Listen, Handler: m}

	if s.config.NoTLS {
		// Plain HTTP/2 mode — for use behind REALITY, nginx, or other TLS terminator.
		srv.Handler = h2c.NewHandler(m, &http2.Server{})
	} else if s.config.RealityPrivateKey != "" {
		// REALITY mode — steals TLS handshake from a real server
		return s.runWithReality(ctx, srv, m)
	} else if s.config.CertFile != "" && s.config.KeyFile != "" {
		// Use existing certificate (e.g., Let's Encrypt managed by certbot)
		cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
		if err != nil {
			return fmt.Errorf("load cert: %w", err)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		}
	} else {
		// Autocert mode (Let's Encrypt automatic)
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.config.Domain),
			Cache:      autocert.DirCache(s.config.CertDir),
		}
		go http.ListenAndServe(":80", certManager.HTTPHandler(nil))
		srv.TLSConfig = certManager.TLSConfig()
		srv.TLSConfig.MinVersion = tls.VersionTLS12
		srv.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
	}

	// Session reaper
	go s.sessionReaper(ctx)

	// Padding config watcher
	if s.config.PaddingConfig != "" {
		go s.watchPaddingConfig(ctx, s.config.PaddingConfig)
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	if s.config.NoTLS {
		log.Printf("Mirage server on %s (plain HTTP/h2c, domain: %s)", s.config.Listen, s.config.Domain)
		return srv.ListenAndServe()
	}
	log.Printf("Mirage server on %s (TLS, domain: %s)", s.config.Listen, s.config.Domain)
	return srv.ListenAndServeTLS("", "")
}

// runWithReality starts the server with REALITY TLS.
// REALITY proxies the TLS handshake to a real server (e.g., troncent.com),
// making the TLS fingerprint identical to that server.
func (s *Server) runWithReality(ctx context.Context, srv *http.Server, handler http.Handler) error {
	privKeyBytes, err := base64.RawURLEncoding.DecodeString(s.config.RealityPrivateKey)
	if err != nil {
		return fmt.Errorf("reality: invalid private key: %w", err)
	}

	shortIDBytes, err := hex.DecodeString(s.config.RealityShortID)
	if err != nil {
		return fmt.Errorf("reality: invalid short id: %w", err)
	}
	var shortID [8]byte
	copy(shortID[:], shortIDBytes)

	dest := s.config.RealityDest
	if dest == "" {
		dest = s.config.RealityServerName + ":443"
	}

	realityCfg := &reality.Config{
		Show:                   s.config.Verbose,
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		Type:                   "tcp",
		Dest:                   dest,
		ServerNames:            map[string]bool{s.config.RealityServerName: true},
		PrivateKey:             privKeyBytes,
		ShortIds:               map[[8]byte]bool{shortID: true},
		MaxTimeDiff:            2 * time.Minute,
		NextProtos:             []string{"h2", "http/1.1"},
		SessionTicketsDisabled: true, // avoid NewSessionTicket size mismatch with target
	}

	ln, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return fmt.Errorf("reality: listen: %w", err)
	}

	realityLn := reality.NewListener(ln, realityCfg)

	// REALITY's Conn is not *tls.Conn, so Go's HTTP/2 auto-negotiation won't work.
	// Use h2c (HTTP/2 cleartext) handler — REALITY already handles encryption,
	// the HTTP layer treats the decrypted stream as plain TCP.
	srv.Handler = h2c.NewHandler(handler, &http2.Server{})

	// Session reaper
	go s.sessionReaper(ctx)
	if s.config.PaddingConfig != "" {
		go s.watchPaddingConfig(ctx, s.config.PaddingConfig)
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
		realityLn.Close()
	}()

	log.Printf("Mirage server on %s (REALITY→%s, domain: %s)", s.config.Listen, dest, s.config.Domain)
	return srv.Serve(realityLn)
}

func (s *Server) getOrCreateSession(sessionID []byte) *serverSession {
	key := string(sessionID)
	s.mu.Lock()
	ss, exists := s.sessions[key]
	if exists {
		s.mu.Unlock()
		ss.touch()
		return ss
	}

	// downstream: mux writes frames here → GET handler ReadFromBlock at client's
	// reported offset. ReplayPipe keeps unacked bytes around so a new GET can
	// resume the byte stream exactly at the client's last-received offset
	// after a carrier reset (no loss, no duplication — the fix for the
	// earlier "bad record mac" class of failures).
	downstream := mux.NewReplayPipe()

	// upstream: POST handler writes data here → mux RecvLoop reads
	upR, upW := io.Pipe()

	sess := mux.NewSession(downstream) // mux writes downstream frames to ReplayPipe
	sess.PaddingOracle = s.morpher     // wire morph engine into mux
	sess.OnStream = func(st *mux.Stream) {
		s.handleProxy(st)
	}

	// Server-side decoy stream generator so the asymmetry of "only client
	// emits decoys" is not itself a fingerprint. Interval randomized around
	// the client's own cadence for the same reason.
	stopDecoys := sess.StartDecoyGenerator(2500 * time.Millisecond)

	ss = &serverSession{
		sess:       sess,
		downstream: downstream,
		upstreamW:  upW,
		upstreamPW: upW,
		stopDecoys: stopDecoys,
	}
	ss.touch()
	s.sessions[key] = ss
	s.mu.Unlock()

	// Push padding config to client
	if cfg := s.paddingCfg.Load(); cfg != nil {
		sess.SendSettings(mux.EncodePaddingConfig(cfg))
	}

	// Start mux recv loop: reads frames from upstream pipe
	go func() {
		if err := sess.RecvLoop(upR); err != nil && err != io.EOF {
			log.Printf("mux recv: %v", err)
		}
		sess.Close()
		ss.cancelDownHandler()
		ss.downstream.Close()
		if ss.stopDecoys != nil {
			ss.stopDecoys()
		}
		s.mu.Lock()
		delete(s.sessions, key)
		s.mu.Unlock()
	}()

	log.Printf("new session")
	return ss
}

func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		s.apiError(w, 401)
		return
	}
	_, sessionID, err := s.auth.Validate(strings.TrimPrefix(hdr, "Bearer "))
	if err != nil {
		s.apiError(w, 401)
		return
	}

	ss := s.getOrCreateSession(sessionID)
	ss.touch()

	// Both directions carry X-Mirage-Rx: the client's report of how many
	// downstream bytes it has received. Use it to trim our downstream
	// replay buffer — bounded memory + no risk of re-sending acked bytes.
	if rxHdr := r.Header.Get(headerMirageRx); rxHdr != "" {
		if rx, err := strconv.ParseUint(rxHdr, 10, 64); err == nil {
			ss.downstream.Ack(rx)
		}
	}

	if r.Method == http.MethodPost {
		s.handleUpstream(w, r, ss)
		return
	}
	s.handleDownstream(w, r, ss)
}

// handleUpstream accepts POST'd upstream mux bytes at an absolute offset
// declared in X-Mirage-Offset, dedupes any overlap the server has already
// received (in case the client is retrying after a failed POST), forwards
// the net-new bytes to the mux RecvLoop, and reports the new total back to
// the client via X-Mirage-Rx.
func (s *Server) handleUpstream(w http.ResponseWriter, r *http.Request, ss *serverSession) {
	postOff, err := parseUintHeader(r.Header.Get(headerMirageOffset))
	if err != nil {
		s.apiError(w, 400)
		return
	}
	expected := ss.upRecv.Load()
	body := r.Body

	// Client offset ahead of ours ⇒ gap: we're missing bytes that would have
	// landed between expected and postOff. Can't recover without those bytes
	// so tear the session down and let the client start fresh.
	if postOff > expected {
		log.Printf("upstream gap: client_off=%d server_expect=%d — tearing session", postOff, expected)
		s.apiError(w, 410) // Gone — session state is unrecoverable
		return
	}
	// Client offset behind ours ⇒ overlap: client is retransmitting bytes
	// we've already forwarded. Skip the overlap.
	if postOff < expected {
		skip := int64(expected - postOff)
		if _, err := io.CopyN(io.Discard, body, skip); err != nil {
			// Short body: client didn't actually retransmit the overlap.
			// No net-new bytes; respond with current ack.
			w.Header().Set(headerMirageRx, strconv.FormatUint(expected, 10))
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	n, _ := io.Copy(ss.upstreamW, body)
	newRecv := ss.upRecv.Add(uint64(n))
	w.Header().Set(headerMirageRx, strconv.FormatUint(newRecv, 10))
	w.WriteHeader(http.StatusOK)
}

// handleDownstream streams downstream mux bytes starting at the client's
// X-Mirage-Rx offset. If the client reports having received past our replay
// base, we just continue from there (possibly replaying unacked bytes).
func (s *Server) handleDownstream(w http.ResponseWriter, r *http.Request, ss *serverSession) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flusher", 500)
		return
	}

	// Client's starting offset. Falls back to 0 if absent (first GET).
	offset, _ := parseUintHeader(r.Header.Get(headerMirageRx))

	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// A session is allowed exactly one active downstream handler. If a new
	// GET arrives while we are still serving, installDownHandler cancels us
	// via ctx so the new handler can own the replay pipe alone.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	gen := ss.installDownHandler(cancel)
	defer ss.releaseDownHandler(gen)

	for {
		data, err := ss.downstream.ReadFromBlock(ctx, offset)
		if len(data) > 0 {
			if _, werr := w.Write(data); werr != nil {
				// Client went away mid-response. Bytes stay in the replay
				// pipe (ReadFromBlock is non-destructive); the next GET
				// will re-request this offset and we'll resend them.
				return
			}
			flusher.Flush()
			offset += uint64(len(data))
			ss.touch()
		}
		if err != nil {
			// ctx.Err() means we were superseded or the session tore down.
			// Unacked bytes stay in replay; successor picks up at its own
			// offset. EOF means the pipe was closed (session reaped).
			return
		}
	}
}

func parseUintHeader(h string) (uint64, error) {
	if h == "" {
		return 0, nil
	}
	return strconv.ParseUint(h, 10, 64)
}

func (s *Server) handleProxy(st *mux.Stream) {
	defer st.Close()

	var buf [2]byte
	if _, err := io.ReadFull(st, buf[:]); err != nil {
		return
	}
	targetLen := binary.BigEndian.Uint16(buf[:])
	if targetLen > 512 {
		return
	}
	targetBuf := make([]byte, targetLen)
	if _, err := io.ReadFull(st, targetBuf); err != nil {
		return
	}
	target := string(targetBuf)

	// "udp:" marker = SOCKS5 UDP ASSOCIATE session; dispatch to the UDP
	// relay which frames datagrams back and forth over the same stream.
	if strings.HasPrefix(target, "udp:") {
		s.handleUDPRelay(st)
		return
	}

	var (
		dest net.Conn
		err  error
	)
	if s.config.Outbound != nil {
		dest, err = s.config.Outbound.DialTarget(target)
	} else {
		// Built-in dialer with TCP keepalive: detects dead targets within
		// ~75s instead of the OS default ~2 hours, so a server that
		// silently drops the connection (NAT timeout, mid-box reboot,
		// etc.) doesn't leave us with a zombie mux stream and goroutines.
		dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		dest, err = dialer.Dial("tcp", target)
	}
	if err != nil {
		if s.config.Verbose {
			log.Printf("dial %s: %v", target, err)
		} else {
			log.Printf("dial failed: %v", err)
		}
		return
	}
	defer dest.Close()

	if s.config.Verbose {
		log.Printf("proxy: %s", target)
	}
	relay.Bidirectional(st, dest)
}

func (s *Server) apiError(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write([]byte(fmt.Sprintf(`{"error":"unauthorized","code":%d}`, code)))
}

func (s *Server) serveWebsite(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		http.ServeFile(w, r, s.config.WebRoot+"/index.html")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(404)
	w.Write([]byte(`<!DOCTYPE html><html><head><title>404</title></head><body><h1>Not Found</h1></body></html>`))
}

// sessionReaper periodically cleans up idle sessions.
func (s *Server) sessionReaper(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now().Unix()
			for key, ss := range s.sessions {
				// 1 hour of idle before reaping. Previously 5 min, which
				// was too aggressive: any network disruption longer than 5
				// min (sing-box restart plus flapping, ISP blip, etc.)
				// would cause the session to be reaped, and when the client
				// eventually reconnected its upAckedOff would no longer
				// match the server's reset upRecv → 410 storm.
				if now-ss.lastActive.Load() > 3600 {
					ss.cancelDownHandler() // kick any in-flight GET handler
					ss.sess.Close()
					ss.downstream.Close()
					ss.upstreamPW.Close() // unblocks RecvLoop goroutine
					if ss.stopDecoys != nil {
						ss.stopDecoys()
					}
					delete(s.sessions, key)
					log.Printf("reaped idle session")
				}
			}
			s.mu.Unlock()
		}
	}
}

// watchPaddingConfig polls the config file and pushes updates to all active sessions.
func (s *Server) watchPaddingConfig(ctx context.Context, path string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newCfg, err := loadPaddingConfigJSON(path)
			if err != nil {
				continue
			}
			oldCfg := s.paddingCfg.Load()
			if reflect.DeepEqual(newCfg, oldCfg) {
				continue
			}
			s.paddingCfg.Store(newCfg)
			s.morpher.UpdateConfig(paddingToMorphConfig(newCfg))
			log.Printf("padding config updated from %s", path)

			// Push to all active sessions
			encoded := mux.EncodePaddingConfig(newCfg)
			s.mu.Lock()
			for _, ss := range s.sessions {
				ss.sess.SendSettings(encoded)
			}
			s.mu.Unlock()
		}
	}
}

// paddingConfigJSON is the JSON representation for the padding config file.
type paddingConfigJSON struct {
	Tau             float64 `json:"tau"`
	EarlyPktCount   int     `json:"early_pkt_count"`
	EarlyPadMin     int     `json:"early_pad_min"`
	EarlyPadMax     int     `json:"early_pad_max"`
	SteadyPadMin    int     `json:"steady_pad_min"`
	SteadyPadMax    int     `json:"steady_pad_max"`
	KeepaliveMin    int     `json:"keepalive_min"`
	KeepaliveMax    int     `json:"keepalive_max"`
	KeepaliveMinSec float32 `json:"keepalive_min_sec"`
	KeepaliveMaxSec float32 `json:"keepalive_max_sec"`
}

func loadPaddingConfigJSON(path string) (*mux.PaddingConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var j paddingConfigJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	cfg := mux.DefaultPaddingConfig()
	if j.Tau > 0 {
		cfg.Tau = j.Tau
	}
	if j.EarlyPktCount > 0 {
		cfg.EarlyPktCount = j.EarlyPktCount
	}
	if j.EarlyPadMin > 0 {
		cfg.EarlyPadMin = uint16(j.EarlyPadMin)
	}
	if j.EarlyPadMax > 0 {
		cfg.EarlyPadMax = uint16(j.EarlyPadMax)
	}
	if j.SteadyPadMin >= 0 {
		cfg.SteadyPadMin = uint16(j.SteadyPadMin)
	}
	if j.SteadyPadMax > 0 {
		cfg.SteadyPadMax = uint16(j.SteadyPadMax)
	}
	if j.KeepaliveMin > 0 {
		cfg.KeepaliveMin = uint16(j.KeepaliveMin)
	}
	if j.KeepaliveMax > 0 {
		cfg.KeepaliveMax = uint16(j.KeepaliveMax)
	}
	if j.KeepaliveMinSec > 0 {
		cfg.KeepaliveMinSec = j.KeepaliveMinSec
	}
	if j.KeepaliveMaxSec > 0 {
		cfg.KeepaliveMaxSec = j.KeepaliveMaxSec
	}
	return cfg, nil
}

// paddingToMorphConfig converts mux.PaddingConfig to morph.Config.
func paddingToMorphConfig(p *mux.PaddingConfig) *morph.Config {
	var sizes []morph.WeightedSize
	for _, fs := range p.FrameSizes {
		sizes = append(sizes, morph.WeightedSize{
			Size:   int(fs.Size),
			Weight: float64(fs.Weight),
		})
	}
	return &morph.Config{
		Tau:            p.Tau,
		EarlyPktCount:  p.EarlyPktCount,
		EarlyPadMu:     int(p.EarlyPadMin),
		EarlyPadSigma:  int(p.EarlyPadMax-p.EarlyPadMin) / 3,
		SteadyPadMu:    int(p.SteadyPadMin),
		SteadyPadSigma: int(p.SteadyPadMax-p.SteadyPadMin) / 3,
		FrameSizes:     sizes,
	}
}
