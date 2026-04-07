package main

import (
	"flag"
	"log"

	"github.com/houden/mirage/internal/client"
)

func main() {
	serverAddr := flag.String("server", "", "server address (e.g. kafuka.sunlawai.com)")
	psk := flag.String("psk", "", "pre-shared key (required)")
	listen := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	flag.Parse()

	if *serverAddr == "" || *psk == "" {
		log.Fatal("--server and --psk are required")
	}

	c := client.New(client.Config{
		ServerAddr: *serverAddr,
		PSK:        *psk,
		Listen:     *listen,
	})

	log.Fatal(c.Run())
}
