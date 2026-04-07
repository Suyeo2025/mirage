package fragment

import (
	"math/rand/v2"
	"net"
	"time"
)

// FragmentClientHello splits a TLS ClientHello across multiple TCP segments
// to defeat GFW's SNI-based DPI which cannot reassemble across segments.
// (Based on IEEE S&P 2025 research)
//
// This operates on the OUTER TLS connection (client → server/CDN),
// while the inner fragmentation engine operates on the inner TLS
// handshake carried inside the QUIC session.
func FragmentClientHello(conn net.Conn, hello []byte) error {
	if len(hello) < 10 {
		_, err := conn.Write(hello)
		return err
	}

	// Fragment 1: TLS record header + partial handshake header (15-30 bytes)
	// This splits the SNI field across segments
	frag1End := 15 + rand.IntN(16)
	if frag1End > len(hello) {
		frag1End = len(hello)
	}
	if _, err := conn.Write(hello[:frag1End]); err != nil {
		return err
	}

	// Small delay to force TCP segment boundary
	time.Sleep(time.Duration(1+rand.IntN(3)) * time.Millisecond)

	if frag1End >= len(hello) {
		return nil
	}

	// Fragment 2: middle portion containing SNI
	mid := frag1End + (len(hello)-frag1End)/2 + rand.IntN(30)
	if mid >= len(hello) {
		mid = len(hello) - 1
	}
	if _, err := conn.Write(hello[frag1End:mid]); err != nil {
		return err
	}

	time.Sleep(time.Duration(1+rand.IntN(3)) * time.Millisecond)

	// Fragment 3: remainder
	if mid < len(hello) {
		if _, err := conn.Write(hello[mid:]); err != nil {
			return err
		}
	}

	return nil
}
