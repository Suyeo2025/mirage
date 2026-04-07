package session

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// ClientSession manages the client-side inner QUIC session.
type ClientSession struct {
	conn     *MemPacketConn
	quicConn *quic.Conn
}

// DialClientSession creates a QUIC session over an existing MemPacketConn.
// The carrier must already be running and bridging packets.
func DialClientSession(ctx context.Context, memConn *MemPacketConn) (*ClientSession, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"mirage-inner"},
	}

	tr := &quic.Transport{Conn: memConn}

	qConn, err := tr.Dial(ctx, &memAddr{}, tlsConf, &quic.Config{
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                15 * time.Second,
		InitialStreamReceiveWindow:     10 * 1024 * 1024, // 10MB — allow large bursts without ACK
		MaxStreamReceiveWindow:         20 * 1024 * 1024,
		InitialConnectionReceiveWindow: 15 * 1024 * 1024,
		MaxConnectionReceiveWindow:     30 * 1024 * 1024,
	})
	if err != nil {
		return nil, err
	}

	return &ClientSession{
		conn:     memConn,
		quicConn: qConn,
	}, nil
}

func (c *ClientSession) OpenStream(ctx context.Context) (*quic.Stream, error) {
	return c.quicConn.OpenStreamSync(ctx)
}

func (c *ClientSession) Close() error {
	c.quicConn.CloseWithError(0, "closed")
	return c.conn.Close()
}

// StreamConn wraps a quic.Stream to implement io.ReadWriteCloser for relay.
type StreamConn struct {
	*quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func NewStreamConn(s *quic.Stream) *StreamConn {
	return &StreamConn{
		Stream:     s,
		localAddr:  &memAddr{},
		remoteAddr: &memAddr{},
	}
}

func (sc *StreamConn) LocalAddr() net.Addr  { return sc.localAddr }
func (sc *StreamConn) RemoteAddr() net.Addr { return sc.remoteAddr }

func (sc *StreamConn) CloseWrite() error {
	sc.Stream.CancelWrite(0)
	return nil
}

func (sc *StreamConn) Close() error {
	sc.Stream.CancelWrite(0)
	sc.Stream.CancelRead(0)
	return nil
}
