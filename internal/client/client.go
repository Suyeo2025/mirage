package client

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/houden/mirage/internal/auth"
	"github.com/houden/mirage/internal/carrier"
	"github.com/houden/mirage/internal/mux"
	"github.com/houden/mirage/internal/relay"
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
	return &Client{config: cfg, auth: auth.New(cfg.PSK), sessionID: sid}
}

func (c *Client) Run() error {
	// upstream: mux writes frames → BufPipe (never blocks) → carrier reads → POST
	upstream := mux.NewBufPipe()

	// downstream: carrier writes from GET response → io.Pipe → mux reads frames
	downR, downW := io.Pipe()

	// mux session writes upstream frames to BufPipe
	sess := mux.NewSession(upstream)

	// carrier bridges mux ↔ HTTPS
	car := carrier.NewClientCarrier(carrier.ClientCarrierConfig{
		ServerAddr:  c.config.ServerAddr,
		Auth:        c.auth,
		SessionID:   c.sessionID,
		Upstream:    upstream,
		DownstreamW: downW,
	})
	go car.Run()

	// mux reads downstream frames from pipe
	go func() {
		if err := sess.RecvLoop(downR); err != nil {
			log.Printf("mux recv: %v", err)
		}
	}()

	log.Printf("SOCKS5 on %s → %s", c.config.Listen, c.config.ServerAddr)

	ln, err := net.Listen("tcp", c.config.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
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
		target = fmt.Sprintf("%s:%d", buf[5:5+dLen], binary.BigEndian.Uint16(buf[5+dLen:7+dLen]))
	case 0x04:
		target = fmt.Sprintf("[%s]:%d", net.IP(buf[4:20]), binary.BigEndian.Uint16(buf[20:22]))
	default:
		return "", fmt.Errorf("unsupported atyp %d", buf[3])
	}
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return target, nil
}
