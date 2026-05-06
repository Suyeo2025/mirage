package admin

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestIsLoopback(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"", false},
		{"localhost", true},
		{"127.0.0.1", true},
		{"127.10.20.30", true},
		{"::1", true},
		{"0.0.0.0", false},
		{"10.0.0.1", false},
		{"8.8.8.8", false},
		{"example.com", false},
		{"2001:db8::1", false},
	}
	for _, c := range cases {
		if got := isLoopback(c.host); got != c.want {
			t.Errorf("isLoopback(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestListenRejectsNonLoopback(t *testing.T) {
	cases := []string{
		"0.0.0.0:0",
		"8.8.8.8:9090",
		"example.com:9090",
		"not-a-host",
	}
	for _, addr := range cases {
		if err := Listen(addr, http.NotFoundHandler()); err == nil {
			t.Errorf("Listen(%q) accepted a non-loopback address", addr)
		}
	}
}

func TestListenServesLoopback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"ok": "yes"})
	})

	// Pick a free port on the loopback rather than a fixed one — CI runners
	// frequently rerun and we don't want a "bind: address already in use".
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()

	if err := Listen(addr, mux); err != nil {
		t.Fatal(err)
	}

	// Tiny grace for the goroutine to bind. If it never comes up the GET
	// below fails fast on connection refused.
	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get("http://" + addr + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"ok"`) {
		t.Fatalf("body = %q, want contains \"ok\"", body)
	}
}
