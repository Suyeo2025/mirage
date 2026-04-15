package outbound

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	M "github.com/sagernet/sing/common/metadata"
	vmess "github.com/sagernet/sing-vmess"
)

const (
	// idleTimeout is how long a connection can be idle (no data read)
	// before it's closed. Active connections reset this on every read.
	idleTimeout = 60 * time.Second

	// drainTimeout is how long the read side gets to finish after the
	// write side is done (CloseWrite called). This covers the gap where
	// VMess/WS can't do half-close: the target doesn't know we're done
	// sending, so we give it this long to finish its response.
	drainTimeout = 30 * time.Second
)

// VMessWSConfig holds VMess+WebSocket outbound configuration.
type VMessWSConfig struct {
	Server string // server address (host or IP)
	Port   uint16 // server port
	UUID   string // VMess user UUID
	WSPath string // WebSocket path, e.g. "/relay"
}

// VMessWSDialer dials targets through a VMess+WebSocket proxy.
type VMessWSDialer struct {
	cfg    VMessWSConfig
	client *vmess.Client
}

// NewVMessWSDialer creates a new VMess+WS outbound dialer.
func NewVMessWSDialer(cfg VMessWSConfig) (*VMessWSDialer, error) {
	client, err := vmess.NewClient(cfg.UUID, "auto", 0)
	if err != nil {
		return nil, fmt.Errorf("vmess client init: %w", err)
	}
	log.Printf("outbound: vmess-ws → %s:%d%s", cfg.Server, cfg.Port, cfg.WSPath)
	return &VMessWSDialer{cfg: cfg, client: client}, nil
}

// DialTarget connects to the target address through the VMess+WS proxy.
func (d *VMessWSDialer) DialTarget(target string) (net.Conn, error) {
	wsURL := fmt.Sprintf("ws://%s:%d%s", d.cfg.Server, d.cfg.Port, d.cfg.WSPath)
	wsDialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
	}
	wsRaw, _, err := wsDialer.Dial(wsURL, http.Header{})
	if err != nil {
		return nil, fmt.Errorf("ws connect %s: %w", wsURL, err)
	}

	baseConn := newWSConn(wsRaw)

	dest := M.ParseSocksaddr(target)
	vmessConn, err := d.client.DialConn(baseConn, dest)
	if err != nil {
		baseConn.Close()
		return nil, fmt.Errorf("vmess dial %s: %w", target, err)
	}

	return &halfCloseConn{Conn: vmessConn, ws: baseConn}, nil
}

// halfCloseConn wraps a net.Conn to handle the fact that VMess+WS
// doesn't support TCP half-close. When relay.Bidirectional finishes
// one direction and calls CloseWrite, we set a short read deadline
// to give the other direction time to finish, then clean up.
type halfCloseConn struct {
	net.Conn
	ws   *wsConn
	once sync.Once
}

func (c *halfCloseConn) CloseWrite() error {
	// The write side is done (client finished sending). VMess/WS can't
	// signal half-close, so set a deadline for the read side to finish.
	// Active reads (data still flowing) will complete before this deadline.
	// Idle reads (target not responding) will timeout and unblock the relay.
	c.ws.setIdleTimeout(drainTimeout)
	return nil
}

func (c *halfCloseConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.ws.Close()
	})
	return err
}

// wsConn adapts gorilla/websocket.Conn to net.Conn for stream-based I/O.
type wsConn struct {
	ws     *websocket.Conn
	reader io.Reader
	mu     sync.Mutex // protects writes
	closed bool
	idle   time.Duration // current idle timeout
}

func newWSConn(ws *websocket.Conn) *wsConn {
	ws.SetReadDeadline(time.Now().Add(idleTimeout))
	return &wsConn{ws: ws, idle: idleTimeout}
}

// setIdleTimeout changes the idle timeout. Next read will use the new value.
func (c *wsConn) setIdleTimeout(d time.Duration) {
	c.idle = d
	c.ws.SetReadDeadline(time.Now().Add(d))
}

func (c *wsConn) Read(b []byte) (int, error) {
	for {
		if c.reader != nil {
			n, err := c.reader.Read(b)
			if n > 0 {
				// Reset idle deadline on successful read — active connections stay alive
				c.ws.SetReadDeadline(time.Now().Add(c.idle))
				return n, nil
			}
			if err != io.EOF {
				return 0, err
			}
			c.reader = nil
		}
		_, reader, err := c.ws.NextReader()
		if err != nil {
			return 0, err
		}
		c.reader = reader
	}
}

func (c *wsConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.ws.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.ws.Close()
}

func (c *wsConn) LocalAddr() net.Addr {
	return c.ws.LocalAddr()
}

func (c *wsConn) RemoteAddr() net.Addr {
	return c.ws.RemoteAddr()
}

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return c.ws.SetWriteDeadline(t)
}

func (c *wsConn) SetReadDeadline(t time.Time) error {
	return c.ws.SetReadDeadline(t)
}

func (c *wsConn) SetWriteDeadline(t time.Time) error {
	return c.ws.SetWriteDeadline(t)
}
