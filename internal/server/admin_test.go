package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminStatusShape(t *testing.T) {
	s := New(Config{
		PSK:    "x" + strings.Repeat("a", 32),
		Domain: "test",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	s.AdminHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var got ServerStats
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SessionCount != 0 {
		t.Errorf("session_count = %d, want 0 (no sessions yet)", got.SessionCount)
	}
	if got.PolicyDenyCnt == 0 {
		t.Errorf("policy_deny_cidrs = 0, want >0 (default deny list should be loaded)")
	}
	if got.OutboundOn {
		t.Errorf("outbound_configured = true, want false (no outbound in test config)")
	}
	if got.UptimeSec < 0 {
		t.Errorf("uptime_sec = %d, want >=0", got.UptimeSec)
	}
}

func TestAdminStatusRejectsNonGet(t *testing.T) {
	s := New(Config{PSK: "x" + strings.Repeat("a", 32), Domain: "test"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/status", nil)
	s.AdminHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST → %d, want 405", rec.Code)
	}
}
