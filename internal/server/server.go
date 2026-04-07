package server

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/houden/mirage/internal/auth"
	"github.com/houden/mirage/internal/mux"
	"github.com/houden/mirage/internal/relay"
	"golang.org/x/crypto/acme/autocert"
)

type Config struct {
	Domain  string
	PSK     string
	WebRoot string
	CertDir string
	Listen  string
}

type serverSession struct {
	sess       *mux.Session
	downstream *mux.BufPipe // mux writes downstream frames here → GET reads
	upstreamW  io.Writer    // POST body data written here → mux RecvLoop reads
}

type Server struct {
	config   Config
	auth     *auth.Auth
	mu       sync.Mutex
	sessions map[string]*serverSession
}

func New(cfg Config) *Server {
	return &Server{
		config:   cfg,
		auth:     auth.New(cfg.PSK),
		sessions: make(map[string]*serverSession),
	}
}

func (s *Server) Run() error {
	m := http.NewServeMux()
	m.HandleFunc("/api/v2/tunnel", s.handleTunnel)
	m.HandleFunc("/api/v1/sync", s.handleTunnel)
	m.HandleFunc("/api/v1/courses/stream", s.handleTunnel)
	m.HandleFunc("/", s.serveWebsite)

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(s.config.Domain),
		Cache:      autocert.DirCache(s.config.CertDir),
	}
	go http.ListenAndServe(":80", certManager.HTTPHandler(nil))

	tlsConfig := certManager.TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	srv := &http.Server{Addr: s.config.Listen, Handler: m, TLSConfig: tlsConfig}
	log.Printf("Mirage server on %s (domain: %s)", s.config.Listen, s.config.Domain)
	return srv.ListenAndServeTLS("", "")
}

func (s *Server) getOrCreateSession(sessionID []byte) *serverSession {
	key := string(sessionID)
	s.mu.Lock()
	ss, exists := s.sessions[key]
	if exists {
		s.mu.Unlock()
		return ss
	}

	// downstream: mux writes frames here → GET handler reads and streams to client
	downstream := mux.NewBufPipe()

	// upstream: POST handler writes data here → mux RecvLoop reads
	upR, upW := io.Pipe()

	sess := mux.NewSession(downstream) // mux writes downstream frames to BufPipe
	sess.OnStream = func(st *mux.Stream) {
		s.handleProxy(st)
	}

	ss = &serverSession{
		sess:       sess,
		downstream: downstream,
		upstreamW:  upW,
	}
	s.sessions[key] = ss
	s.mu.Unlock()

	// Start mux recv loop: reads frames from upstream pipe
	go func() {
		if err := sess.RecvLoop(upR); err != nil && err != io.EOF {
			log.Printf("mux recv: %v", err)
		}
		sess.Close()
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

	if r.Method == http.MethodPost {
		// Upstream: POST body contains mux frames
		io.Copy(ss.upstreamW, r.Body)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Downstream: GET → stream mux frames as chunked video/mp4
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flusher", 500)
		return
	}

	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Read from downstream BufPipe, write to response.
	// Use WaitAndDrain to batch: sends all buffered data at once,
	// reducing flush() syscall overhead for high throughput.
	for {
		data, err := ss.downstream.WaitAndDrain()
		if len(data) > 0 {
			w.Write(data)
			flusher.Flush()
		}
		if err != nil {
			return
		}
		if r.Context().Err() != nil {
			return
		}
	}
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

	dest, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		return
	}
	defer dest.Close()

	log.Printf("proxy: %s", target)
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
