package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

// ServerStats is the snapshot returned by /status. Field names use snake_case
// because the consumer is plain shell + jq, not a Go program. The struct is
// intentionally flat: no nested deep state, no pointer chains — easy to grep
// in journalctl when you can't get jq.
type ServerStats struct {
	UptimeSec      int64          `json:"uptime_sec"`
	SessionCount   int            `json:"session_count"`
	Sessions       []SessionStats `json:"sessions"`
	PolicyAllowCnt int            `json:"policy_allow_cidrs"`
	PolicyDenyCnt  int            `json:"policy_deny_cidrs"`
	OutboundOn     bool           `json:"outbound_configured"`
	RealityOn      bool           `json:"reality_enabled"`
}

// SessionStats is the per-session line of ServerStats. Only short IDs and
// counters are exposed — the PSK / token / sessionID raw bytes never leave
// the process, even on the loopback admin endpoint.
type SessionStats struct {
	IDShort       string `json:"id_short"`
	IdleSec       int64  `json:"idle_sec"`
	UpRecv        uint64 `json:"up_recv_bytes"`
	HasDownstream bool   `json:"has_downstream_handler"`
}

// Stats samples the live server state once. Holds s.mu for the duration of
// the snapshot; sessions are typically O(few) so this is cheap. Per-session
// counters are atomic loads, no lock needed.
func (s *Server) Stats() ServerStats {
	now := time.Now()
	s.mu.Lock()
	sessions := make([]SessionStats, 0, len(s.sessions))
	for k, ss := range s.sessions {
		// Short id = first 4 bytes hex. Enough to distinguish sessions in
		// a handful of rows without exposing the full ID a misbehaving
		// admin reader could replay.
		short := ""
		if len(k) >= 4 {
			short = hex.EncodeToString([]byte(k[:4]))
		}
		ss.downCancelMu.Lock()
		hasDown := ss.downCancel != nil
		ss.downCancelMu.Unlock()
		sessions = append(sessions, SessionStats{
			IDShort:       short,
			IdleSec:       now.Unix() - ss.lastActive.Load(),
			UpRecv:        ss.upRecv.Load(),
			HasDownstream: hasDown,
		})
	}
	count := len(s.sessions)
	s.mu.Unlock()

	allowCnt, denyCnt := 0, 0
	if s.policy != nil {
		allowCnt = len(s.policy.allow)
		denyCnt = len(s.policy.deny)
	}

	return ServerStats{
		UptimeSec:      int64(time.Since(s.startTime).Seconds()),
		SessionCount:   count,
		Sessions:       sessions,
		PolicyAllowCnt: allowCnt,
		PolicyDenyCnt:  denyCnt,
		OutboundOn:     s.config.Outbound != nil,
		RealityOn:      s.config.RealityPrivateKey != "",
	}
}

// AdminHandler returns an http.Handler that serves /status as JSON. Mount
// it on the loopback admin listener registered by internal/admin.Listen.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Stats())
	})
	return mux
}
