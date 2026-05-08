package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/houden/mirage/internal/mux"
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

// TestHandleDownstreamDoesNotTouchSession is the regression test for the
// zombie-session bug: previously handleDownstream called ss.touch() after
// every successful Write, so a session whose client process had died kept
// looking "active" to the reaper for as long as the kernel TCP buffer
// accepted decoy bytes. Now lastActive only reflects inbound activity.
//
// We exercise the loop by writing one small frame into the downstream
// ReplayPipe, letting handleDownstream forward it to a stub ResponseWriter,
// and asserting that ss.lastActive did not advance.
func TestHandleDownstreamDoesNotTouchSession(t *testing.T) {
	pipe := mux.NewReplayPipe()
	ss := &serverSession{
		downstream: pipe,
	}
	// Pin lastActive to a fixed point in the past so any touch would visibly
	// jump it forward.
	const pinned = int64(1_000_000)
	ss.lastActive.Store(pinned)

	pipe.Write([]byte("hello"))

	// Run handleDownstream against a recorder; cancel after a beat so the
	// loop returns and we can inspect state.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v2/tunnel", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	s := &Server{}
	s.handleDownstream(rec, req, ss)

	if got := ss.lastActive.Load(); got != pinned {
		t.Fatalf("lastActive moved from %d to %d — handleDownstream is still touching the session", pinned, got)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("response body empty — handleDownstream didn't forward the frame")
	}
}

// TestTunnelRejectsNonGetPostMethods verifies the tunnel endpoint replies 405
// for any HTTP method other than GET (downstream) or POST (upstream). Without
// this, an unrelated method (PUT, DELETE, etc.) would fall through to the
// downstream handler and tie up the session's single-handler slot.
func TestTunnelRejectsNonGetPostMethods(t *testing.T) {
	s := New(Config{PSK: "x" + strings.Repeat("a", 32), Domain: "test"})

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		// Mint a fresh token per iteration — auth.Validate enforces nonce
		// replay protection, so a single shared token would 401 on the
		// second method and we'd never reach the method switch we are
		// trying to test.
		tok, err := s.auth.Generate(1, []byte("0123456789abcdef"))
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, "/api/v2/tunnel", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		s.handleTunnel(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s → %d, want 405", method, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != "GET, POST" {
			t.Errorf("%s Allow header = %q, want \"GET, POST\"", method, got)
		}
	}
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
