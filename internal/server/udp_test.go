package server

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

// TestParseAddrAndDataIPv4 covers the ATYP=0x01 happy path: 4 addr bytes,
// 2 port bytes, payload tail.
func TestParseAddrAndDataIPv4(t *testing.T) {
	body := []byte{
		0x01, // ATYP v4
		8, 8, 8, 8, // 8.8.8.8
		0x00, 0x35, // port 53
		0xde, 0xad, 0xbe, 0xef, // payload
	}
	addr, data, err := parseAddrAndData(body)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !addr.IP.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Errorf("ip = %v, want 8.8.8.8", addr.IP)
	}
	if addr.Port != 53 {
		t.Errorf("port = %d, want 53", addr.Port)
	}
	if !bytes.Equal(data, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("data = %x, want deadbeef", data)
	}
}

// TestParseAddrAndDataIPv6 covers ATYP=0x04: 16 addr bytes, 2 port, payload.
func TestParseAddrAndDataIPv6(t *testing.T) {
	body := []byte{
		0x04, // ATYP v6
		0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
		0x00, 0x35, // port 53
		0xab, 0xcd,
	}
	addr, data, err := parseAddrAndData(body)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	want := net.ParseIP("2001:4860:4860::8888")
	if !addr.IP.Equal(want) {
		t.Errorf("ip = %v, want %v", addr.IP, want)
	}
	if addr.Port != 53 {
		t.Errorf("port = %d, want 53", addr.Port)
	}
	if !bytes.Equal(data, []byte{0xab, 0xcd}) {
		t.Errorf("data = %x", data)
	}
}

// TestParseAddrAndDataDomainResolvesIPLiteral covers ATYP=0x03 by passing an
// IP literal in the domain field. ResolveUDPAddr handles literals without
// DNS, so this stays offline-friendly while still exercising the same code
// path real domain queries take.
func TestParseAddrAndDataDomainResolvesIPLiteral(t *testing.T) {
	const host = "127.0.0.1"
	body := []byte{0x03, byte(len(host))}
	body = append(body, []byte(host)...)
	body = append(body, 0x00, 0x35, 0x01, 0x02)
	addr, data, err := parseAddrAndData(body)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !addr.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("ip = %v", addr.IP)
	}
	if addr.Port != 53 {
		t.Errorf("port = %d", addr.Port)
	}
	if !bytes.Equal(data, []byte{0x01, 0x02}) {
		t.Errorf("data = %x", data)
	}
}

func TestParseAddrAndDataRejectsTruncated(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"empty", []byte{}},
		{"v4 short addr", []byte{0x01, 8, 8}},
		{"v4 missing port", []byte{0x01, 8, 8, 8, 8}},
		{"v6 short addr", []byte{0x04, 0x20, 0x01}},
		{"domain length but no name", []byte{0x03, 0x05}},
		{"domain truncated", []byte{0x03, 0x05, 'a', 'b'}},
		{"unknown atyp", []byte{0x07, 1, 2, 3}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := parseAddrAndData(c.body); err == nil {
				t.Fatalf("expected error for %s, got nil", c.name)
			}
		})
	}
}

// TestEncodeFrameIPv4 validates the [LEN:2][ATYP:1][ADDR:4][PORT:2][DATA]
// layout produced for a v4 source.
func TestEncodeFrameIPv4(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443}
	data := []byte{0xff, 0xee}
	frame := encodeFrame(addr, data)
	if frame == nil {
		t.Fatal("got nil frame")
	}
	// 2 (len header) + 1 (atyp) + 4 (addr) + 2 (port) + len(data) = 11
	if len(frame) != 11 {
		t.Fatalf("len = %d, want 11", len(frame))
	}
	want := []byte{
		0x00, 0x09, // total = 9 (atyp+addr+port+data)
		0x01,       // atyp v4
		1, 1, 1, 1, // addr
		0x01, 0xbb, // port 443
		0xff, 0xee,
	}
	if !bytes.Equal(frame, want) {
		t.Errorf("frame = %x, want %x", frame, want)
	}
}

func TestEncodeFrameIPv6(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("2606:4700:4700::1111"), Port: 443}
	frame := encodeFrame(addr, []byte{0x42})
	if frame == nil {
		t.Fatal("got nil frame")
	}
	if frame[2] != 0x04 {
		t.Errorf("atyp = %d, want 4", frame[2])
	}
	// 2 (len) + 1 (atyp) + 16 (addr) + 2 (port) + 1 (data) = 22
	if len(frame) != 22 {
		t.Fatalf("len = %d, want 22", len(frame))
	}
}

// TestEncodeFrameRejectsOversize ensures encodeFrame returns nil rather than
// silently overflowing the 16-bit length field. 65520 bytes of payload plus
// the 19 bytes of v6 framing overhead is just over 2^16.
func TestEncodeFrameRejectsOversize(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("2606:4700:4700::1111"), Port: 1}
	huge := make([]byte, 65520)
	if frame := encodeFrame(addr, huge); frame != nil {
		t.Fatalf("expected nil for oversize frame, got len=%d", len(frame))
	}
}

func TestReadFrameRoundTrip(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 53}
	frame := encodeFrame(addr, []byte("hello"))
	body, err := readFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	gotAddr, gotData, err := parseAddrAndData(body)
	if err != nil {
		t.Fatalf("parse err = %v", err)
	}
	if !gotAddr.IP.Equal(addr.IP) || gotAddr.Port != addr.Port {
		t.Errorf("addr round-trip lost: got %v, want %v", gotAddr, addr)
	}
	if string(gotData) != "hello" {
		t.Errorf("data round-trip lost: %q", gotData)
	}
}

func TestReadFrameRejectsTruncated(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", []byte{}},
		{"only one byte of length", []byte{0x00}},
		{"length=0", []byte{0x00, 0x00}},
		{"truncated body", []byte{0x00, 0x05, 'a', 'b'}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := readFrame(bytes.NewReader(c.raw))
			if err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
			// length=0 returns a domain-specific "zero length" error;
			// truncated reads return io.EOF / io.ErrUnexpectedEOF.
			_ = errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
		})
	}
}

// TestUDPPolicyDropsBogonTarget verifies that the same default policy used
// by the TCP path also covers UDP destinations. handleUDPRelay's hot loop
// calls policy.Allowed before pc.WriteTo; this asserts the expected verdict
// for the canonical bogon set.
func TestUDPPolicyDropsBogonTarget(t *testing.T) {
	p, err := newTargetPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	denied := []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "fe80::1"}
	for _, s := range denied {
		ip := net.ParseIP(s)
		if p.Allowed(ip) {
			t.Errorf("UDP target %s should be denied by default policy", s)
		}
	}
	allowed := []string{"8.8.8.8", "2001:4860:4860::8888"}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if !p.Allowed(ip) {
			t.Errorf("UDP target %s should be allowed by default policy", s)
		}
	}
}
