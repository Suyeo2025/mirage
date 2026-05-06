package client

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// runHandshake drives handleSocks5 against a net.Pipe whose client side it
// feeds with the supplied request bytes. Returns whatever handleSocks5
// returned plus the bytes it wrote back (greeting reply + request reply).
func runHandshake(t *testing.T, request []byte) (byte, string, error, []byte) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()

	type result struct {
		cmd    byte
		target string
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		c, tg, e := handleSocks5(serverSide)
		serverSide.Close()
		resCh <- result{c, tg, e}
	}()

	var written bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(&written, clientSide)
	}()

	if _, err := clientSide.Write(request); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Half-close write so the server-side goroutine sees EOF after reading
	// the request, in case it is waiting for more bytes than we sent.
	if cw, ok := clientSide.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}

	res := <-resCh
	wg.Wait()
	return res.cmd, res.target, res.err, written.Bytes()
}

func TestSocks5IPv4Connect(t *testing.T) {
	req := bytes.Buffer{}
	req.Write([]byte{0x05, 0x01, 0x00})                                  // greeting: ver, 1 method, NO_AUTH
	req.Write([]byte{0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0x01, 0xbb})    // CONNECT 8.8.8.8:443
	cmd, target, err, _ := runHandshake(t, req.Bytes())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if cmd != 0x01 {
		t.Errorf("cmd = %d, want 1", cmd)
	}
	if target != "8.8.8.8:443" {
		t.Errorf("target = %q, want 8.8.8.8:443", target)
	}
}

func TestSocks5IPv6Connect(t *testing.T) {
	req := bytes.Buffer{}
	req.Write([]byte{0x05, 0x01, 0x00})
	// CONNECT [2001:4860:4860::8888]:443
	req.Write([]byte{0x05, 0x01, 0x00, 0x04})
	req.Write([]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88})
	req.Write([]byte{0x01, 0xbb})
	_, target, err, _ := runHandshake(t, req.Bytes())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if target != "[2001:4860:4860::8888]:443" {
		t.Errorf("target = %q", target)
	}
}

func TestSocks5DomainConnect(t *testing.T) {
	req := bytes.Buffer{}
	req.Write([]byte{0x05, 0x01, 0x00})
	host := "example.com"
	req.Write([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))})
	req.WriteString(host)
	req.Write([]byte{0x01, 0xbb})
	_, target, err, _ := runHandshake(t, req.Bytes())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if target != "example.com:443" {
		t.Errorf("target = %q", target)
	}
}

// TestSocks5RejectsTruncatedIPv4 is the regression test for the bug where
// a 7-byte request (down from the 10 IPv4 actually needs) was accepted and
// produced a "0.0.0.0:0" target out of the unwritten tail of the buffer.
func TestSocks5RejectsTruncatedIPv4(t *testing.T) {
	req := bytes.Buffer{}
	req.Write([]byte{0x05, 0x01, 0x00})                  // greeting
	req.Write([]byte{0x05, 0x01, 0x00, 0x01, 8, 8, 8})   // header + 3 of 4 addr bytes — short
	_, _, err, _ := runHandshake(t, req.Bytes())
	if err == nil {
		t.Fatal("expected error on truncated IPv4 request, got nil")
	}
	if !strings.Contains(err.Error(), "v4 addr") && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want v4 addr / EOF error", err)
	}
}

func TestSocks5RejectsTruncatedIPv6(t *testing.T) {
	req := bytes.Buffer{}
	req.Write([]byte{0x05, 0x01, 0x00})
	req.Write([]byte{0x05, 0x01, 0x00, 0x04, 0x20, 0x01}) // header + 2 of 16 addr bytes
	_, _, err, _ := runHandshake(t, req.Bytes())
	if err == nil {
		t.Fatal("expected error on truncated IPv6 request, got nil")
	}
}

func TestSocks5HandshakeDeadline(t *testing.T) {
	// Stall: open the conn but never write anything. Without the deadline,
	// handleSocks5 would block forever; with it, ReadFull should fail
	// inside ~5 s (we only wait a bit beyond that to be safe in CI).
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, _, err := handleSocks5(serverSide)
		serverSide.Close()
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected handshake to fail on deadline, got nil")
		}
		if elapsed := time.Since(start); elapsed > 7*time.Second {
			t.Fatalf("handshake took %v, deadline should fire in ~5s", elapsed)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("handshake did not return within 8s — deadline not enforced")
	}
}
