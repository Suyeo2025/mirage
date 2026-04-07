package main

import (
	"flag"
	"log"

	"github.com/houden/mirage/internal/server"
)

func main() {
	domain := flag.String("domain", "kafuka.sunlawai.com", "TLS domain")
	psk := flag.String("psk", "", "pre-shared key (required)")
	webRoot := flag.String("web-root", "./web", "static website directory")
	certDir := flag.String("cert-dir", "/opt/mirage/certs", "autocert cache directory")
	listen := flag.String("listen", ":443", "listen address")
	flag.Parse()

	if *psk == "" {
		log.Fatal("--psk is required")
	}

	srv := server.New(server.Config{
		Domain:  *domain,
		PSK:     *psk,
		WebRoot: *webRoot,
		CertDir: *certDir,
		Listen:  *listen,
	})

	log.Fatal(srv.Run())
}
