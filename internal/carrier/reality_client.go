// REALITY client handshake for Mirage.
//
// Protocol (from Xray-core/sing-box source):
//   1. BuildHandshakeState → get hello + ECDHE keys
//   2. Populate sessionId: [version:3][0:1][timestamp:4][shortId:8]
//   3. Marshal ClientHello with zeros as sessionId → this is the AAD
//   4. ECDH(ephemeralKey, serverPubKey) → HKDF(SHA256, Random[:20], "REALITY") → authKey
//   5. AES-GCM(authKey, nonce=Random[20:], plaintext=sessionId[:16], aad=marshaledRaw) → encrypted
//   6. Set hello.SessionId = encrypted, let HandshakeContext re-marshal and send
//   7. Server zeros sessionId in received Raw to reconstruct AAD, decrypts, validates
package carrier

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

func realityDial(ctx context.Context, conn net.Conn, serverPubKey []byte, shortID [8]byte, sni string) (net.Conn, error) {
	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         sni,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)

	if err := uConn.BuildHandshakeState(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("reality: build: %w", err)
	}

	hello := uConn.HandshakeState.Hello

	// Extract ECDHE key — prefer pure X25519 (REALITY server tries this first)
	ksKeys := uConn.HandshakeState.State13.KeyShareKeys
	if ksKeys == nil {
		conn.Close()
		return nil, fmt.Errorf("reality: no KeyShareKeys")
	}
	ecdheKey := ksKeys.Ecdhe
	if ecdheKey == nil {
		ecdheKey = ksKeys.MlkemEcdhe
	}
	if ecdheKey == nil {
		conn.Close()
		return nil, fmt.Errorf("reality: no ECDHE key")
	}

	// Derive AuthKey: ECDH + HKDF
	serverPub, err := ecdh.X25519().NewPublicKey(serverPubKey)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reality: bad key: %w", err)
	}
	authKey, err := ecdheKey.ECDH(serverPub)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reality: ecdh: %w", err)
	}
	hkdfR := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY"))
	if _, err := io.ReadFull(hkdfR, authKey); err != nil {
		conn.Close()
		return nil, fmt.Errorf("reality: hkdf: %w", err)
	}

	// Build sessionId plaintext
	var sessionPlain [16]byte
	sessionPlain[0] = 1 // version
	binary.BigEndian.PutUint32(sessionPlain[4:8], uint32(time.Now().Unix()))
	copy(sessionPlain[8:16], shortID[:])

	// Compute AAD: marshal with zero sessionId
	hello.SessionId = make([]byte, 32)
	if err := uConn.MarshalClientHello(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("reality: marshal: %w", err)
	}
	aad := make([]byte, len(hello.Raw))
	copy(aad, hello.Raw)

	// AES-GCM encrypt sessionId
	block, _ := aes.NewCipher(authKey)
	gcm, _ := cipher.NewGCM(block)
	var encSessionId [32]byte
	gcm.Seal(encSessionId[:0], hello.Random[20:], sessionPlain[:], aad)

	// Set encrypted sessionId — HandshakeContext will re-marshal
	hello.SessionId = encSessionId[:]

	if err := uConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("reality: handshake: %w", err)
	}

	return uConn, nil
}
