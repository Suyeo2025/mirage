package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/houden/mirage/internal/server"
)

func main() {
	domain := flag.String("domain", "", "TLS domain (required)")
	psk := flag.String("psk", "", "pre-shared key (required)")
	webRoot := flag.String("web-root", "./web", "static website directory")
	certDir := flag.String("cert-dir", "/opt/mirage/certs", "autocert cache directory")
	certFile := flag.String("cert", "", "TLS certificate file (skips autocert if set)")
	keyFile := flag.String("key", "", "TLS private key file (skips autocert if set)")
	noTLS := flag.Bool("no-tls", false, "plain HTTP mode (for use behind REALITY/nginx)")
	realityDest := flag.String("reality-dest", "", "REALITY handshake target (e.g. troncent.com:443)")
	realitySNI := flag.String("reality-sni", "", "REALITY server name (e.g. troncent.com)")
	realityKey := flag.String("reality-private-key", "", "REALITY x25519 private key (base64)")
	realityShortID := flag.String("reality-short-id", "", "REALITY short ID (hex)")
	listen := flag.String("listen", ":443", "listen address")
	paddingConfig := flag.String("padding-config", "", "padding config JSON file (optional, hot-reloaded)")
	verbose := flag.Bool("verbose", false, "verbose logging (includes target addresses)")
	flag.Parse()

	if *psk == "" || *domain == "" {
		log.Fatal("--domain and --psk are required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(server.Config{
		Domain:        *domain,
		PSK:           *psk,
		WebRoot:       *webRoot,
		CertDir:       *certDir,
		CertFile:      *certFile,
		KeyFile:       *keyFile,
		NoTLS:             *noTLS,
		RealityDest:       *realityDest,
		RealityServerName: *realitySNI,
		RealityPrivateKey: *realityKey,
		RealityShortID:    *realityShortID,
		Listen:            *listen,
		PaddingConfig: *paddingConfig,
		Verbose:       *verbose,
	})

	if err := srv.Run(ctx); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
