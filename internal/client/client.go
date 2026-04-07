package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/houden/mirage/internal/auth"
	"github.com/houden/mirage/internal/carrier"
	"github.com/houden/mirage/internal/relay"
	"github.com/houden/mirage/internal/session"
)

type Config struct {
	ServerAddr string
	PSK        string
	Listen     string
}

type Client struct {
	config    Config
	auth      *auth.Auth
	sessionID []byte
}

func New(cfg Config) *Client {
	sid := make([]byte, 16)
	rand.Read(sid)
	return &Client{
		config:    cfg,
		auth:      auth.New(cfg.PSK),
		sessionID: sid,
	}
}

func (c *Client) Run() error {
	ctx := context.Background()

	// Create the in-memory QUIC transport (not connected yet)
	memConn := session.NewMemPacketConn(512)

	// Start carrier FIRST — so it can deliver QUIC handshake packets
	car := carrier.NewClientCarrier(carrier.ClientCarrierConfig{
		ServerAddr: c.config.ServerAddr,
		Auth:       c.auth,
		SessionID:  c.sessionID,
		Outbound:   memConn.Outbound(),
		Deliver:    memConn.Deliver,
	})
	go car.Run()
	defer car.Stop()

	// NOW create the QUIC session — handshake packets flow through carrier
	sess, err := session.DialClientSession(ctx, memConn)
	if err != nil {
		return fmt.Errorf("dial session: %w", err)
	}
	defer sess.Close()

	log.Printf("inner QUIC session established")

	// Start SOCKS5 listener
	ln, err := net.Listen("tcp", c.config.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	log.Printf("SOCKS5 on %s → %s (Turbo Tunnel)", c.config.Listen, c.config.ServerAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go c.handleConn(ctx, sess, conn)
	}
}

func (c *Client) handleConn(ctx context.Context, sess *session.ClientSession, conn net.Conn) {
	defer conn.Close()

	target, err := handleSocks5(conn)
	if err != nil {
		log.Printf("socks5: %v", err)
		return
	}

	stream, err := sess.OpenStream(ctx)
	if err != nil {
		log.Printf("open stream: %v", err)
		return
	}

	sc := session.NewStreamConn(stream)
	defer sc.Close()

	// Send target address (length-prefixed)
	targetBytes := []byte(target)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(targetBytes)))
	sc.Write(lenBuf[:])
	sc.Write(targetBytes)

	relay.Bidirectional(conn, sc)
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
		target = fmt.Sprintf("%s:%d", buf[5:5+dLen], binary.BigEndian.Uint16(buf[5+dLen:7+dLen]))
	case 0x04:
		target = fmt.Sprintf("[%s]:%d", net.IP(buf[4:20]), binary.BigEndian.Uint16(buf[20:22]))
	default:
		return "", fmt.Errorf("unsupported atyp %d", buf[3])
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return target, nil
}
