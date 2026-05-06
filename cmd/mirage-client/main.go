package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/houden/mirage/internal/client"
)

func main() {
	serverAddr := flag.String("server", "", "server address (e.g. 45.78.77.18:9445)")
	psk := flag.String("psk", "", "pre-shared key (required)")
	listen := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	userID := flag.Uint("user-id", 1, "user ID for multi-user support")
	realityPubKey := flag.String("reality-public-key", "", "REALITY server public key (base64)")
	realityShortID := flag.String("reality-short-id", "", "REALITY short ID (hex)")
	realitySNI := flag.String("reality-sni", "", "REALITY server name (e.g. troncent.com)")
	adminListen := flag.String("admin-listen", "", "loopback host:port for the JSON /status endpoint (e.g. 127.0.0.1:1099). Empty = disabled.")
	flag.Parse()

	// PSK falls back to env so systemd can pass it through a 0600
	// EnvironmentFile instead of leaking on the ExecStart line.
	if *psk == "" {
		*psk = os.Getenv("MIRAGE_PSK")
	}

	if *serverAddr == "" || *psk == "" {
		log.Fatal("--server and --psk (or MIRAGE_PSK env) are required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c := client.New(client.Config{
		ServerAddr:       *serverAddr,
		PSK:              *psk,
		Listen:           *listen,
		UserID:           uint16(*userID),
		RealityPublicKey: *realityPubKey,
		RealityShortID:   *realityShortID,
		RealitySNI:       *realitySNI,
		AdminListen:      *adminListen,
	})

	if err := c.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
