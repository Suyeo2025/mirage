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
	flag.Parse()

	if *serverAddr == "" || *psk == "" {
		log.Fatal("--server and --psk are required")
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
	})

	if err := c.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
