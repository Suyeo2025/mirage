package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// ServerSession manages the server-side inner QUIC session.
// Multiple carrier connections can feed packets to the same session.
type ServerSession struct {
	conn     *MemPacketConn
	listener *quic.Listener
	mu       sync.Mutex
	sessions map[string]*quic.Conn // sessionID -> QUIC conn
}

func NewServerSession() (*ServerSession, error) {
	conn := NewMemPacketConn(256)

	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"mirage-inner"},
	}

	tr := &quic.Transport{Conn: conn}
	ln, err := tr.Listen(tlsConf, &quic.Config{
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		Allow0RTT:       true,
	})
	if err != nil {
		return nil, err
	}

	return &ServerSession{
		conn:     conn,
		listener: ln,
		sessions: make(map[string]*quic.Conn),
	}, nil
}

// Accept waits for a new inner QUIC connection (called once per session).
func (s *ServerSession) Accept(ctx context.Context) (*quic.Conn, error) {
	return s.listener.Accept(ctx)
}

// DeliverPacket feeds a QUIC packet from the carrier into the session.
func (s *ServerSession) DeliverPacket(data []byte) {
	s.conn.Deliver(data)
}

// Outbound returns the channel of QUIC packets to send via carrier.
func (s *ServerSession) Outbound() <-chan []byte {
	return s.conn.Outbound()
}

func (s *ServerSession) Close() error {
	s.conn.Close()
	return s.listener.Close()
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
