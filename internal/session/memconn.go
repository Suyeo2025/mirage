package session

import (
	"net"
	"sync"
	"time"
)

// MemPacketConn is an in-memory net.PacketConn that lets QUIC run without
// touching the real network. QUIC packets written here are picked up by the
// carrier layer; packets from the carrier are fed in via Deliver().
type MemPacketConn struct {
	inbound  chan []byte
	outbound chan []byte
	addr     net.Addr
	closed   chan struct{}
	once     sync.Once
}

func NewMemPacketConn(bufSize int) *MemPacketConn {
	return &MemPacketConn{
		inbound:  make(chan []byte, bufSize),
		outbound: make(chan []byte, bufSize),
		addr:     &memAddr{},
		closed:   make(chan struct{}),
	}
}

// ReadFrom is called by quic-go to receive packets.
func (m *MemPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case data := <-m.inbound:
		n := copy(p, data)
		return n, m.addr, nil
	case <-m.closed:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo is called by quic-go to send packets. The carrier goroutine
// reads from Outbound() to ship them over HTTP.
func (m *MemPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case m.outbound <- buf:
		return len(p), nil
	case <-m.closed:
		return 0, net.ErrClosed
	}
}

// Deliver feeds a packet received from the carrier into the QUIC stack.
func (m *MemPacketConn) Deliver(data []byte) {
	select {
	case m.inbound <- data:
	case <-m.closed:
	}
}

// Outbound returns the channel the carrier reads from.
func (m *MemPacketConn) Outbound() <-chan []byte {
	return m.outbound
}

func (m *MemPacketConn) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

func (m *MemPacketConn) LocalAddr() net.Addr                { return m.addr }
func (m *MemPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *MemPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MemPacketConn) SetWriteDeadline(t time.Time) error { return nil }

type memAddr struct{}

func (a *memAddr) Network() string { return "mem" }
func (a *memAddr) String() string  { return "mem:0" }
