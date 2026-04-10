package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/houden/mirage/internal/outbound"
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
	outboundServer := flag.String("outbound-server", "", "outbound VMess+WS server address (host:port)")
	outboundUUID := flag.String("outbound-uuid", "", "outbound VMess user UUID")
	outboundWSPath := flag.String("outbound-ws-path", "", "outbound WebSocket path (e.g. /relay)")
	flag.Parse()

	if *psk == "" || *domain == "" {
		log.Fatal("--domain and --psk are required")
	}

	// Initialize outbound proxy if configured
	var ob outbound.Dialer
	if *outboundServer != "" && *outboundUUID != "" {
		host, portStr, err := splitHostPort(*outboundServer)
		if err != nil {
			log.Fatalf("invalid --outbound-server: %v", err)
		}
		port, err := parsePort(portStr)
		if err != nil {
			log.Fatalf("invalid --outbound-server port: %v", err)
		}
		wsPath := *outboundWSPath
		if wsPath == "" {
			wsPath = "/"
		}
		ob, err = outbound.NewVMessWSDialer(outbound.VMessWSConfig{
			Server: host,
			Port:   port,
			UUID:   *outboundUUID,
			WSPath: wsPath,
		})
		if err != nil {
			log.Fatalf("outbound init: %v", err)
		}
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
		Outbound:      ob,
	})

	if err := srv.Run(ctx); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func splitHostPort(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	return host, port, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}
