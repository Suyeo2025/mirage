package client

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/houden/mirage/internal/carrier"
)

// ClientStats is the JSON body served at /status on the client admin
// endpoint. It composes carrier health (the high-signal field for live
// incidents) with a few client-shaped fields.
type ClientStats struct {
	UptimeSec      int64                `json:"uptime_sec"`
	SessionIDShort string               `json:"session_id_short"`
	Listen         string               `json:"listen"`
	ServerAddr     string               `json:"server_addr"`
	RealityOn      bool                 `json:"reality_enabled"`
	Carrier        carrier.CarrierStats `json:"carrier"`
}

// adminHandler returns the loopback /status handler. It reads c.live on
// every request rather than capturing a fixed pointer in the closure, so
// stats reflect the currently-active session — including after a 410
// rebuild swapped in a fresh session+carrier underneath.
func (c *Client) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cur := c.live.Load()
		stats := ClientStats{
			Listen:     c.config.Listen,
			ServerAddr: c.config.ServerAddr,
			RealityOn:  c.config.RealityPublicKey != "",
		}
		if cur != nil {
			short := ""
			if len(cur.sessionID) >= 4 {
				short = hex.EncodeToString(cur.sessionID[:4])
			}
			stats.UptimeSec = int64(time.Since(cur.started).Seconds())
			stats.SessionIDShort = short
			stats.Carrier = cur.car.Stats()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stats)
	})
	return mux
}
