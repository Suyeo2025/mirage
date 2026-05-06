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

// adminHandler builds the loopback admin handler for a running client.
// Closure captures car and the run-scoped startTime / sessionID so the
// caller (Run) can keep them as locals instead of mutating Client.
func adminHandler(cfg Config, sessionID []byte, started time.Time, car *carrier.ClientCarrier) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		short := ""
		if len(sessionID) >= 4 {
			short = hex.EncodeToString(sessionID[:4])
		}
		stats := ClientStats{
			UptimeSec:      int64(time.Since(started).Seconds()),
			SessionIDShort: short,
			Listen:         cfg.Listen,
			ServerAddr:     cfg.ServerAddr,
			RealityOn:      cfg.RealityPublicKey != "",
			Carrier:        car.Stats(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stats)
	})
	return mux
}
