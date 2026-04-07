package carrier

import (
	"encoding/binary"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/houden/mirage/internal/auth"
)

type ServerCarrier struct {
	auth         *auth.Auth
	mu           sync.Mutex
	sessions     map[string]*SessionLink
	onNewSession func(sessionID []byte, link *SessionLink)
}

type SessionLink struct {
	Inbound  chan []byte // carrier → QUIC
	Outbound chan []byte // QUIC → carrier
}

func NewSessionLink() *SessionLink {
	return &SessionLink{
		Inbound:  make(chan []byte, 512),
		Outbound: make(chan []byte, 512),
	}
}

type ServerCarrierConfig struct {
	Auth         *auth.Auth
	OnNewSession func(sessionID []byte, link *SessionLink)
}

func NewServerCarrier(cfg ServerCarrierConfig) *ServerCarrier {
	return &ServerCarrier{
		auth:         cfg.Auth,
		sessions:     make(map[string]*SessionLink),
		onNewSession: cfg.OnNewSession,
	}
}

func (sc *ServerCarrier) HandleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	link := sc.authenticate(w, r)
	if link == nil {
		return
	}

	for {
		var pktLen uint16
		if err := binary.Read(r.Body, binary.BigEndian, &pktLen); err != nil {
			break
		}
		pkt := make([]byte, pktLen)
		if _, err := io.ReadFull(r.Body, pkt); err != nil {
			break
		}
		select {
		case link.Inbound <- pkt:
		default:
			log.Printf("carrier: inbound full, drop")
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (sc *ServerCarrier) HandleStream(w http.ResponseWriter, r *http.Request) {
	link := sc.authenticate(w, r)
	if link == nil {
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flusher", 500)
		return
	}

	// Disguise as video streaming — the most common CDN traffic type
	// A chunked video/mp4 response at 40 Mbps is perfectly normal CDN behavior
	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering (nginx/CDN)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()

	// Keepalive timer: send small padding during idle periods
	// to simulate video buffering / heartbeat. Prevents the connection
	// from looking "dead" during proxy idle, which would be unusual
	// for a video stream.
	keepalive := time.NewTicker(5 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-link.Outbound:
			var lenBuf [2]byte
			binary.BigEndian.PutUint16(lenBuf[:], uint16(len(pkt)))
			w.Write(lenBuf[:])
			w.Write(pkt)
			flusher.Flush()
		case <-keepalive.C:
			// Inject small keepalive padding (looks like video buffer probe)
			// QUIC will silently ignore these non-QUIC bytes
			padSize := 64 + mrand.Intn(128) // 64-192 bytes
			pad := make([]byte, padSize)
			var lenBuf [2]byte
			binary.BigEndian.PutUint16(lenBuf[:], uint16(padSize))
			w.Write(lenBuf[:])
			w.Write(pad)
			flusher.Flush()
		}
	}
}

func (sc *ServerCarrier) authenticate(w http.ResponseWriter, r *http.Request) *SessionLink {
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		return nil
	}
	token := strings.TrimPrefix(hdr, "Bearer ")

	_, sessionID, err := sc.auth.Validate(token)
	if err != nil {
		return nil
	}

	sidKey := string(sessionID)
	sc.mu.Lock()
	link, exists := sc.sessions[sidKey]
	if !exists {
		link = NewSessionLink()
		sc.sessions[sidKey] = link
		sc.mu.Unlock()
		log.Printf("new session established")
		if sc.onNewSession != nil {
			go sc.onNewSession(sessionID, link)
		}
	} else {
		sc.mu.Unlock()
	}
	return link
}
