package carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/houden/mirage/internal/auth"
)

type ClientCarrier struct {
	serverURL string
	auth      *auth.Auth
	sessionID []byte
	client    *http.Client
	outbound  <-chan []byte
	deliver   func(data []byte)
	ctx       context.Context
	cancel    context.CancelFunc
}

type ClientCarrierConfig struct {
	ServerAddr string
	Auth       *auth.Auth
	SessionID  []byte
	Outbound   <-chan []byte
	Deliver    func(data []byte)
}

func NewClientCarrier(cfg ClientCarrierConfig) *ClientCarrier {
	ctx, cancel := context.WithCancel(context.Background())
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 4,
		DisableCompression:  true,
		IdleConnTimeout:     90 * time.Second,
	}
	return &ClientCarrier{
		serverURL: "https://" + cfg.ServerAddr,
		auth:      cfg.Auth,
		sessionID: cfg.SessionID,
		client:    &http.Client{Transport: tr},
		outbound:  cfg.Outbound,
		deliver:   cfg.Deliver,
		ctx:       ctx,
		cancel:    cancel,
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
	token, err := c.auth.Generate(1, c.sessionID)
	if err != nil {
		log.Printf("carrier: generate token: %v", err)
		return ""
	}
	return token
}

func (c *ClientCarrier) upstreamLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case pkt := <-c.outbound:
			buf := encodePacket(pkt)
		drain:
			for {
				select {
				case extra := <-c.outbound:
					buf = append(buf, encodePacket(extra)...)
				default:
					break drain
				}
			}
			if err := c.sendUpstream(buf); err != nil {
				log.Printf("carrier up: %v", err)
				time.Sleep(200 * time.Millisecond)
			}
		}
	}
}

func (c *ClientCarrier) downstreamLoop() {
	for {
		if c.ctx.Err() != nil {
			return
		}
		if err := c.openDownstream(); err != nil {
			log.Printf("carrier down: %v", err)
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func (c *ClientCarrier) sendUpstream(data []byte) error {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost,
		c.serverURL+"/api/v2/upload", bytes.NewReader(data))
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

func (c *ClientCarrier) openDownstream() error {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet,
		c.serverURL+"/api/v2/stream", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.freshToken())

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	for {
		var pktLen uint16
		if err := binary.Read(resp.Body, binary.BigEndian, &pktLen); err != nil {
			return err
		}
		pkt := make([]byte, pktLen)
		if _, err := io.ReadFull(resp.Body, pkt); err != nil {
			return err
		}
		c.deliver(pkt)
	}
}

func encodePacket(pkt []byte) []byte {
	buf := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(pkt)))
	copy(buf[2:], pkt)
	return buf
}
