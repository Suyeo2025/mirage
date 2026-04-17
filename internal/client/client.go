package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
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
		go c.handleConn(sess, conn)
	}
}

func (c *Client) handleConn(sess *mux.Session, conn net.Conn) {
	defer conn.Close()

	target, err := handleSocks5(conn)
	if err != nil {
		log.Printf("socks5: %v", err)
		return
	}

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
}

func handleSocks5(conn net.Conn) (string, error) {
	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return "", fmt.Errorf("bad greeting")
	}
	conn.Write([]byte{0x05, 0x00})
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[1] != 0x01 {
		return "", fmt.Errorf("bad request")
	}
	var target string
	switch buf[3] {
	case 0x01:
		target = fmt.Sprintf("%s:%d", net.IP(buf[4:8]), binary.BigEndian.Uint16(buf[8:10]))
	case 0x03:
		dLen := int(buf[4])
		if 5+dLen+2 > n {
			return "", fmt.Errorf("domain name truncated")
		}
		target = fmt.Sprintf("%s:%d", buf[5:5+dLen], binary.BigEndian.Uint16(buf[5+dLen:7+dLen]))
	case 0x04:
		target = fmt.Sprintf("[%s]:%d", net.IP(buf[4:20]), binary.BigEndian.Uint16(buf[20:22]))
	default:
		return "", fmt.Errorf("unsupported atyp %d", buf[3])
	}
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return target, nil
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
