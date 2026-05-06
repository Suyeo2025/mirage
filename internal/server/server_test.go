package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// trackingWriter records peak concurrent Write calls. Used to detect whether
// per-session POST serialization is actually holding a lock across io.Copy.
type trackingWriter struct {
	sleep    time.Duration
	inFlight atomic.Int32
	peak     atomic.Int32
}

func (t *trackingWriter) Write(p []byte) (int, error) {
	cur := t.inFlight.Add(1)
	defer t.inFlight.Add(-1)
	for {
		p := t.peak.Load()
		if cur <= p || t.peak.CompareAndSwap(p, cur) {
			break
		}
	}
	if t.sleep > 0 {
		time.Sleep(t.sleep)
	}
	return len(p), nil
}

// TestHandleUpstreamSerializesConcurrentPOSTs verifies the upMu lock serializes
// concurrent POSTs against the same session. Without it, an attacker holding
// the PSK could fire parallel POSTs that race the expected/upRecv check,
// producing an interleaved byte stream that corrupts mux frames.
//
// Two POSTs with the same offset 0 and distinct bodies are fired concurrently;
// the trackingWriter sleeps 30 ms inside Write to widen the race window. With
// the lock, exactly one Write is in flight at a time. Without it, the second
// POST sees expected==0 before the first finishes and races into Write.
func TestHandleUpstreamSerializesConcurrentPOSTs(t *testing.T) {
	tw := &trackingWriter{sleep: 30 * time.Millisecond}
	ss := &serverSession{upstreamW: tw, upstreamPW: nil}
	s := &Server{}

	const n = 4
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/api/v2/tunnel", strings.NewReader("AAAA"))
			req.Header.Set(headerMirageOffset, "0")
			rec := httptest.NewRecorder()
			s.handleUpstream(rec, req, ss)
		}()
	}
	wg.Wait()

	if got := tw.peak.Load(); got > 1 {
		t.Fatalf("peak concurrent Write = %d, want 1 (upMu not serializing)", got)
	}
}
