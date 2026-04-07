package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

type Auth struct {
	key    [32]byte
	maxAge time.Duration
	mu     sync.Mutex
	seen   map[[12]byte]time.Time
}

const maxSeenNonces = 100_000

func New(psk string) *Auth {
	// Derive key using Argon2id (resistant to brute-force on weak PSKs)
	salt := sha256.Sum256([]byte("MIRAGE-AUTH-SALT-V2"))
	derived := argon2.IDKey([]byte(psk), salt[:16], 1, 64*1024, 4, 32)
	var key [32]byte
	copy(key[:], derived)
	a := &Auth{
		key:    key,
		maxAge: 30 * time.Second,
		seen:   make(map[[12]byte]time.Time),
	}
	go a.cleanupLoop()
	return a
}

// Generate creates an auth token. Format:
// Base64(nonce:12 || AES-256-GCM(key, nonce, timestamp:8|userID:2|sessionID:16|random:6, "MIRAGE-AUTH-V1"))
func (a *Auth) Generate(userID uint16, sessionID []byte) (string, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}

	plaintext := make([]byte, 32)
	binary.BigEndian.PutUint64(plaintext[0:8], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(plaintext[8:10], userID)
	if len(sessionID) >= 16 {
		copy(plaintext[10:26], sessionID[:16])
	}
	rand.Read(plaintext[26:32])

	block, err := aes.NewCipher(a.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce[:], plaintext, []byte("MIRAGE-AUTH-V2"))
	out := make([]byte, 12+len(ciphertext))
	copy(out[0:12], nonce[:])
	copy(out[12:], ciphertext)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Validate checks a token. Returns userID and sessionID on success.
func (a *Auth) Validate(token string) (uint16, []byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, nil, errors.New("invalid base64")
	}
	if len(raw) < 12+32+16 {
		return 0, nil, errors.New("token too short")
	}

	var nonce [12]byte
	copy(nonce[:], raw[0:12])

	block, err := aes.NewCipher(a.key[:])
	if err != nil {
		return 0, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, nil, err
	}

	plaintext, err := gcm.Open(nil, nonce[:], raw[12:], []byte("MIRAGE-AUTH-V2"))
	if err != nil {
		return 0, nil, errors.New("decryption failed")
	}

	ts := binary.BigEndian.Uint64(plaintext[0:8])
	tokenTime := time.Unix(int64(ts), 0)
	if time.Since(tokenTime).Abs() > a.maxAge {
		return 0, nil, errors.New("token expired")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.seen[nonce]; exists {
		return 0, nil, errors.New("replay detected")
	}
	if len(a.seen) >= maxSeenNonces {
		// Evict oldest entries instead of rejecting legitimate tokens (DoS prevention)
		now := time.Now()
		for k, exp := range a.seen {
			if now.After(exp) || len(a.seen) >= maxSeenNonces {
				delete(a.seen, k)
			}
			if len(a.seen) < maxSeenNonces*9/10 {
				break // evict ~10%
			}
		}
	}
	a.seen[nonce] = time.Now().Add(a.maxAge * 2)

	userID := binary.BigEndian.Uint16(plaintext[8:10])
	sessionID := make([]byte, 16)
	copy(sessionID, plaintext[10:26])
	return userID, sessionID, nil
}

func (a *Auth) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	for range ticker.C {
		a.mu.Lock()
		now := time.Now()
		for k, exp := range a.seen {
			if now.After(exp) {
				delete(a.seen, k)
			}
		}
		a.mu.Unlock()
	}
}
