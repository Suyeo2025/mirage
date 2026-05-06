// Package admin runs a tiny loopback-only HTTP listener that exposes
// runtime stats from the server or client process. The intent is the
// minimum surface needed to diagnose a live system without ssh-and-grep
// of journalctl: per-session counters, carrier health, policy stats.
//
// The listener is opt-in via --admin-listen and refuses to bind anywhere
// outside the loopback range. SOCKS5-style "anyone who reaches the port
// can read your secrets" exposure is unacceptable for an endpoint that
// reveals byte counters and session IDs.
package admin

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

// Listen starts an HTTP server on addr serving handler. addr MUST resolve
// to a loopback address (127.0.0.0/8, ::1, or "localhost"); anything else
// is a configuration error and surfaces as a returned error rather than a
// silent bind to 0.0.0.0.
//
// On success the listener runs in a background goroutine. The caller does
// not get a shutdown handle — admin endpoints exit with the process.
func Listen(addr string, handler http.Handler) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("admin: invalid --admin-listen %q: %w", addr, err)
	}
	if !isLoopback(host) {
		return fmt.Errorf("admin: --admin-listen must bind to loopback (127.0.0.1, ::1, localhost), got %q", host)
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
		// Same ReadHeaderTimeout rationale as the main server: bound the
		// time a stalled client can hold us in header read.
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("admin: listen %q: %w", addr, err)
	}
	go func() {
		log.Printf("admin: serving on %s", addr)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("admin: serve: %v", err)
		}
	}()
	return nil
}

// isLoopback reports whether host (the hostname half of a host:port) is on
// the loopback. Empty string ("the wildcard, bind to all") is rejected on
// purpose — admin must be a deliberate localhost-only choice.
func isLoopback(host string) bool {
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A non-IP that isn't "localhost" — could be a hostname that resolves
		// to a public IP. Refuse rather than risk it.
		return false
	}
	return ip.IsLoopback()
}
