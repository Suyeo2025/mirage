package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/houden/mirage/internal/auth"
	"github.com/houden/mirage/internal/carrier"
	"github.com/houden/mirage/internal/relay"
	"github.com/houden/mirage/internal/session"
	"golang.org/x/crypto/acme/autocert"
)

type Config struct {
	Domain  string
	PSK     string
	WebRoot string
	CertDir string
	Listen  string
}

type Server struct {
	config  Config
	auth    *auth.Auth
	carrier *carrier.ServerCarrier
}

func New(cfg Config) *Server {
	a := auth.New(cfg.PSK)

	s := &Server{
		config: cfg,
		auth:   a,
	}

	s.carrier = carrier.NewServerCarrier(carrier.ServerCarrierConfig{
		Auth:         a,
		OnNewSession: s.handleNewSession,
	})

	return s
}

func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/upload", s.authGate(s.carrier.HandleUpload))
	mux.HandleFunc("/api/v2/stream", s.authGate(s.carrier.HandleStream))
	mux.HandleFunc("/", s.serveWebsite)

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(s.config.Domain),
		Cache:      autocert.DirCache(s.config.CertDir),
	}

	// HTTP-01 challenge on port 80
	go func() {
		log.Printf("HTTP-01 challenge listener on :80")
		http.ListenAndServe(":80", certManager.HTTPHandler(nil))
	}()

	tlsConfig := certManager.TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	srv := &http.Server{
		Addr:    s.config.Listen,
		Handler: mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Mirage server on %s (domain: %s)", s.config.Listen, s.config.Domain)
	return srv.ListenAndServeTLS("", "")
}

// authGate wraps a handler: if auth fails, serve website instead.
func (s *Server) authGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.serveWebsite(w, r)
			return
		}
		// Let the carrier handler do its own auth validation
		// If the carrier returns false (auth failed), we fall through here
		next(w, r)
	}
}

func (s *Server) serveWebsite(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, fmt.Sprintf("%s/index.html", s.config.WebRoot))
}

// handleNewSession is called when a new inner session is established.
// It creates a QUIC server session and bridges it with the carrier link.
func (s *Server) handleNewSession(sessionID []byte, link *carrier.SessionLink) {
	log.Printf("new session from carrier")

	sess, err := session.NewServerSession()
	if err != nil {
		log.Printf("create server session: %v", err)
		return
	}
	defer sess.Close()

	// Bridge: carrier link ↔ QUIC session
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Carrier → QUIC session
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-link.Inbound:
				sess.DeliverPacket(pkt)
			}
		}
	}()

	// QUIC session → Carrier
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-sess.Outbound():
				select {
				case link.Outbound <- pkt:
				default:
				}
			}
		}
	}()

	// Accept QUIC connection from inner session
	qConn, err := sess.Accept(ctx)
	if err != nil {
		log.Printf("accept inner QUIC: %v", err)
		return
	}

	// Handle streams (each = one proxied TCP connection)
	for {
		stream, err := qConn.AcceptStream(ctx)
		if err != nil {
			log.Printf("accept stream: %v", err)
			return
		}
		go s.handleStream(stream)
	}
}

func (s *Server) handleStream(stream io.ReadWriteCloser) {
	defer stream.Close()

	// First message on the stream: target address (length-prefixed string)
	var buf [2]byte
	if _, err := io.ReadFull(stream, buf[:]); err != nil {
		log.Printf("read target len: %v", err)
		return
	}
	targetLen := int(buf[0])<<8 | int(buf[1])
	if targetLen > 512 {
		log.Printf("target too long: %d", targetLen)
		return
	}
	targetBuf := make([]byte, targetLen)
	if _, err := io.ReadFull(stream, targetBuf); err != nil {
		log.Printf("read target: %v", err)
		return
	}
	target := string(targetBuf)

	// Dial destination
	dest, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		return
	}
	defer dest.Close()

	log.Printf("tunnel: %s", target)
	relay.Bidirectional(stream, dest)
}
