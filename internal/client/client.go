package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/houden/mirage/internal/auth"
	"github.com/houden/mirage/internal/carrier"
	"github.com/houden/mirage/internal/morph"
	"github.com/houden/mirage/internal/mux"
	"github.com/houden/mirage/internal/relay"
)

type Config struct {
	ServerAddr string
	PSK        string
	Listen     string
	UserID     uint16 // configurable user ID (default 1)

	// REALITY config (optional)
	RealityPublicKey string
	RealityShortID   string
	RealitySNI       string
}

type Client struct {
	config    Config
	auth      *auth.Auth
	sessionID []byte
	morpher   *morph.Morpher
}

func New(cfg Config) *Client {
	sid := make([]byte, 16)
	rand.Read(sid)
	if cfg.UserID == 0 {
		cfg.UserID = 1
	}
	return &Client{
		config:    cfg,
		auth:      auth.New(cfg.PSK),
		sessionID: sid,
		morpher:   morph.New(nil), // defaults; updated by server CmdSettings
	}
}

func (c *Client) Run(ctx context.Context) error {
	// upstream: mux writes frames → ReplayPipe → carrier Snapshot+POST.
	// ReplayPipe is offset-aware: POST body is read non-destructively from
	// the last-acknowledged byte, letting a failed or reset POST be retried
	// without losing or duplicating bytes.
	upstream := mux.NewReplayPipe()

	// downstream: carrier writes from GET response → BufPipe → mux reads frames.
	// BufPipe (non-blocking writes) decouples the carrier from the mux RecvLoop.
	// Replay on the downstream side is done server-side; the client only tracks
	// a received-byte counter that it reports back via request headers.
	downstream := mux.NewBufPipe()

	// mux session writes upstream frames to the replay pipe.
	sess := mux.NewSession(upstream)
	sess.PaddingOracle = c.morpher // wire morph engine into mux

	// Handle server-pushed padding config
	sess.OnSettings = func(data []byte) {
		cfg, err := mux.DecodePaddingConfig(data)
		if err != nil {
			return
		}
		c.morpher.UpdateConfig(paddingToMorphConfig(cfg))
		log.Printf("padding config updated from server")
	}

	// Start decoy stream generator to drown inner TLS handshake patterns
	// (Xue et al. USENIX 2024: multiplexing reduces detection >70%)
	stopDecoys := sess.StartDecoyGenerator(2 * time.Second)
	defer stopDecoys()

	// carrier bridges mux ↔ HTTPS (or REALITY TLS)
	car := carrier.NewClientCarrier(carrier.ClientCarrierConfig{
		ServerAddr:       c.config.ServerAddr,
		Auth:             c.auth,
		SessionID:        c.sessionID,
		UserID:           c.config.UserID,
		Upstream:         upstream,
		DownstreamW:      downstream,
		RealityPublicKey: c.config.RealityPublicKey,
		RealityShortID:   c.config.RealityShortID,
		RealitySNI:       c.config.RealitySNI,
	})
	go car.Run()

	// mux reads downstream frames from BufPipe
	go func() {
		if err := sess.RecvLoop(downstream); err != nil {
			log.Printf("mux recv: %v", err)
		}
	}()

	log.Printf("SOCKS5 on %s → %s", c.config.Listen, c.config.ServerAddr)

	ln, err := net.Listen("tcp", c.config.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		ln.Close()
		car.Stop()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("accept: %v", err)
			continue
		}
		// TCP keepalive: detect dead apps within ~75s instead of waiting for
		// the OS default (~2 hours). Without this, a crashed/disappeared
		// SOCKS5 client leaves us holding a mux.Stream + 3 goroutines per
		// connection forever.
		if tcp, ok := conn.(*net.TCPConn); ok {
			tcp.SetKeepAlive(true)
			tcp.SetKeepAlivePeriod(30 * time.Second)
		}
		go c.handleConn(sess, conn)
	}
}

func (c *Client) handleConn(sess *mux.Session, conn net.Conn) {
	defer conn.Close()

	cmd, target, err := handleSocks5(conn)
	if err != nil {
		log.Printf("socks5: %v", err)
		return
	}

	switch cmd {
	case 0x01: // CONNECT — classic TCP relay over mux.
		stream, err := sess.OpenStream()
		if err != nil {
			log.Printf("open stream: %v", err)
			return
		}
		defer stream.Close()

		targetBytes := []byte(target)
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(targetBytes)))
		stream.Write(lenBuf[:])
		stream.Write(targetBytes)

		relay.Bidirectional(conn, stream)

	case 0x03: // UDP ASSOCIATE — spawn a UDP relay per the SOCKS5 spec.
		if err := c.handleUDPAssociate(sess, conn); err != nil {
			log.Printf("udp associate: %v", err)
		}

	default:
		log.Printf("socks5: unsupported cmd %d", cmd)
	}
}

// handleSocks5 performs the SOCKS5 method negotiation + request parse, writes
// the initial negotiation reply, and returns the requested CMD and (for
// CONNECT) the target. The request reply itself is NOT written — the caller
// is responsible for sending the appropriate reply once it knows what bind
// endpoint to advertise (different between CONNECT and UDP ASSOCIATE).
//
// All field-sized reads go through io.ReadFull so a short / truncated frame
// fails loudly instead of silently zero-filling the back of the buffer
// (the previous handler would happily produce a "0.0.0.0:0" target out of
// a 7-byte IPv4 request). A 5-second handshake deadline keeps a stalled
// client from holding the accept goroutine and its mux stream forever.
func handleSocks5(conn net.Conn) (byte, string, error) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// Greeting: [VER:1][NMETHODS:1][METHODS:NMETHODS]
	var greet [2]byte
	if _, err := io.ReadFull(conn, greet[:]); err != nil {
		return 0, "", fmt.Errorf("greeting: %w", err)
	}
	if greet[0] != 0x05 {
		return 0, "", fmt.Errorf("bad SOCKS version %d", greet[0])
	}
	if nMethods := int(greet[1]); nMethods > 0 {
		if _, err := io.ReadFull(conn, make([]byte, nMethods)); err != nil {
			return 0, "", fmt.Errorf("methods: %w", err)
		}
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return 0, "", err
	}

	// Request: [VER:1][CMD:1][RSV:1][ATYP:1] then ATYP-specific addr+port
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, "", fmt.Errorf("request header: %w", err)
	}
	if hdr[0] != 0x05 {
		return 0, "", fmt.Errorf("request bad SOCKS version %d", hdr[0])
	}
	cmd := hdr[1]

	var target string
	switch hdr[3] {
	case 0x01: // IPv4: 4 addr + 2 port
		var b [6]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return 0, "", fmt.Errorf("v4 addr: %w", err)
		}
		target = fmt.Sprintf("%s:%d", net.IP(b[:4]), binary.BigEndian.Uint16(b[4:6]))
	case 0x04: // IPv6: 16 addr + 2 port
		var b [18]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return 0, "", fmt.Errorf("v6 addr: %w", err)
		}
		target = fmt.Sprintf("[%s]:%d", net.IP(b[:16]), binary.BigEndian.Uint16(b[16:18]))
	case 0x03: // domain: 1 length + N + 2 port
		var lb [1]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return 0, "", fmt.Errorf("domain length: %w", err)
		}
		dLen := int(lb[0])
		if dLen == 0 {
			return 0, "", fmt.Errorf("zero-length domain")
		}
		b := make([]byte, dLen+2)
		if _, err := io.ReadFull(conn, b); err != nil {
			return 0, "", fmt.Errorf("domain: %w", err)
		}
		target = fmt.Sprintf("%s:%d", b[:dLen], binary.BigEndian.Uint16(b[dLen:dLen+2]))
	default:
		return 0, "", fmt.Errorf("unsupported atyp %d", hdr[3])
	}

	switch cmd {
	case 0x01: // CONNECT — success reply with dummy bind (0.0.0.0:0).
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return cmd, target, nil
	case 0x03: // UDP ASSOCIATE — caller sends reply after binding relay.
		return cmd, target, nil
	default: // BIND (0x02) or anything else — reject cleanly.
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return 0, "", fmt.Errorf("unsupported cmd 0x%02x", cmd)
	}
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
		EarlyPadMu:     int(p.EarlyPadMin), // PaddingConfig min/max → Gaussian mu/sigma
		EarlyPadSigma:  int(p.EarlyPadMax-p.EarlyPadMin) / 3,
		SteadyPadMu:    int(p.SteadyPadMin),
		SteadyPadSigma: int(p.SteadyPadMax-p.SteadyPadMin) / 3,
		FrameSizes:     sizes,
	}
}
