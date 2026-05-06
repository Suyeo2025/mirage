package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/houden/mirage/internal/admin"
	"github.com/houden/mirage/internal/auth"
	"github.com/houden/mirage/internal/carrier"
	"github.com/houden/mirage/internal/morph"
	"github.com/houden/mirage/internal/mux"
	"github.com/houden/mirage/internal/relay"
)

// rebuildCooldown bounds how often the supervisor will reconstruct the
// session+carrier pair after a 410. If the server is wedged and emits 410
// every reconnect, the cooldown stops us from saturating its CPU and our
// log volume; legitimate single-shot 410s pay only 2 s of latency before
// SOCKS5 traffic is flowing again.
const rebuildCooldown = 2 * time.Second

type Config struct {
	ServerAddr string
	PSK        string
	Listen     string
	UserID     uint16 // configurable user ID (default 1)

	// REALITY config (optional)
	RealityPublicKey string
	RealityShortID   string
	RealitySNI       string

	// AdminListen is an optional loopback host:port. When non-empty the
	// client serves a JSON /status endpoint there for live diagnostics.
	// internal/admin.Listen refuses to bind anywhere off the loopback.
	AdminListen string
}

type Client struct {
	config  Config
	auth    *auth.Auth
	morpher *morph.Morpher

	// live holds the active mux.Session + ClientCarrier + sessionID. The
	// supervisor goroutine atomically swaps in a freshly built liveSession
	// whenever the carrier reports SessionLost (HTTP 410 from the server,
	// meaning our byte-stream offset has drifted from server-side state).
	// The accept loop and the admin /status handler each Load() to find
	// the current session without locking.
	live atomic.Pointer[liveSession]
}

// liveSession is the immutable tuple of state for one client incarnation.
// On rebuild a brand-new liveSession is constructed and atomically swapped
// in; the old one's goroutines drain to EOF as their pipes close.
type liveSession struct {
	sess       *mux.Session
	car        *carrier.ClientCarrier
	sessionID  []byte
	started    time.Time
	stopDecoys func()
}

func New(cfg Config) *Client {
	if cfg.UserID == 0 {
		cfg.UserID = 1
	}
	return &Client{
		config:  cfg,
		auth:    auth.New(cfg.PSK),
		morpher: morph.New(nil), // defaults; updated by server CmdSettings
	}
}

// build constructs a fresh session+carrier pair with a new random sessionID.
// The mux RecvLoop and carrier loops are launched into their own goroutines.
// The caller is expected to atomically install the result via c.live.Store.
func (c *Client) build() *liveSession {
	sid := make([]byte, 16)
	rand.Read(sid)

	// upstream: mux frames → ReplayPipe → carrier Snapshot+POST.
	// downstream: carrier writes from GET → BufPipe → mux reads.
	upstream := mux.NewReplayPipe()
	downstream := mux.NewBufPipe()

	sess := mux.NewSession(upstream)
	sess.PaddingOracle = c.morpher
	sess.OnSettings = func(data []byte) {
		cfg, err := mux.DecodePaddingConfig(data)
		if err != nil {
			return
		}
		c.morpher.UpdateConfig(paddingToMorphConfig(cfg))
		log.Printf("padding config updated from server")
	}
	stopDecoys := sess.StartDecoyGenerator(2 * time.Second)

	car := carrier.NewClientCarrier(carrier.ClientCarrierConfig{
		ServerAddr:       c.config.ServerAddr,
		Auth:             c.auth,
		SessionID:        sid,
		UserID:           c.config.UserID,
		Upstream:         upstream,
		DownstreamW:      downstream,
		RealityPublicKey: c.config.RealityPublicKey,
		RealityShortID:   c.config.RealityShortID,
		RealitySNI:       c.config.RealitySNI,
	})
	go car.Run()
	go func() {
		if err := sess.RecvLoop(downstream); err != nil {
			log.Printf("mux recv: %v", err)
		}
	}()

	return &liveSession{
		sess:       sess,
		car:        car,
		sessionID:  sid,
		started:    time.Now(),
		stopDecoys: stopDecoys,
	}
}

func (c *Client) Run(ctx context.Context) error {
	c.live.Store(c.build())

	// SOCKS5 listener is a single bind that survives session rebuilds.
	// Tearing it down on 410 would interrupt every in-flight inbound
	// connection and could race the OS port reuse window; instead we
	// keep the listener and let new accepts attach to whatever live
	// session is current at Accept time.
	ln, err := net.Listen("tcp", c.config.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	log.Printf("SOCKS5 on %s → %s", c.config.Listen, c.config.ServerAddr)

	// Supervisor: rebuild on SessionLost (410) until ctx is done.
	go c.supervise(ctx)

	if c.config.AdminListen != "" {
		// Admin reads c.live.Load() per request, so it always reports the
		// currently-active session+carrier — including across rebuilds.
		if err := admin.Listen(c.config.AdminListen, c.adminHandler()); err != nil {
			return err
		}
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		ln.Close()
		if cur := c.live.Load(); cur != nil {
			cur.car.Stop()
		}
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
		cur := c.live.Load()
		if cur == nil {
			conn.Close()
			continue
		}
		go c.handleConn(cur.sess, conn)
	}
}

// supervise watches the current carrier's SessionLost channel and rebuilds
// the live session+carrier pair when the server returns 410. The previous
// implementation called log.Fatalf and relied on systemd to restart the
// process; this works under any supervisor (systemd, launchd, docker, none)
// and avoids the brief outage of a process restart.
func (c *Client) supervise(ctx context.Context) {
	for {
		cur := c.live.Load()
		if cur == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-cur.car.SessionLost():
			log.Printf("client: rebuilding session after 410")
			// Cooldown before rebuild — protects a wedged server from
			// receiving a tight loop of new sessions, and gives in-flight
			// SOCKS5 connections a moment to notice their streams ended.
			select {
			case <-ctx.Done():
				return
			case <-time.After(rebuildCooldown):
			}
			// Tear down the old incarnation. car already self-cancelled
			// inside signalSessionLost; sess.Close releases mux streams so
			// any blocked relay.Bidirectional copies wake up and exit.
			cur.stopDecoys()
			cur.sess.Close()
			c.live.Store(c.build())
		}
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
	nMethods := int(greet[1])
	if nMethods == 0 {
		// RFC 1928: NMETHODS=0 is malformed. Reply NO_ACCEPTABLE_METHODS
		// and bail rather than auto-replying NO_AUTH (which would let a
		// confused or hostile client think it negotiated something).
		conn.Write([]byte{0x05, 0xff})
		return 0, "", fmt.Errorf("nmethods=0")
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, "", fmt.Errorf("methods: %w", err)
	}
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		// We only support NO_AUTH; tell the client none of its offered
		// methods are acceptable per RFC 1928 §3.
		conn.Write([]byte{0x05, 0xff})
		return 0, "", fmt.Errorf("client did not offer NO_AUTH (methods=%v)", methods)
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
