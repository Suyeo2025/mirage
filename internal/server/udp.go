package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/houden/mirage/internal/mux"
)

// udpRelayIdleTimeout bounds the lifetime of a UDP relay with no datagrams
// in either direction. Matches the client-side limit; primarily a
// defence-in-depth so server-side goroutines cannot accumulate even if
// the client's own teardown path is ever broken.
const udpRelayIdleTimeout = 3 * time.Minute

// handleUDPRelay terminates a mux stream whose target is "udp:" — framed
// UDP datagrams flow both ways on the stream, each carrying its own
// destination (upstream) or source (downstream) address. A single
// net.PacketConn handles all target addresses for this association; that's
// fine because UDP is connectionless and WriteTo/ReadFrom do all the work.
//
// Wire format per frame (same both directions):
//
//	[LEN:2][ATYP:1][ADDR][PORT:2][DATA]
func (s *Server) handleUDPRelay(st *mux.Stream) {
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Printf("udp relay: listen: %v", err)
		return
	}
	defer pc.Close()

	if s.config.Verbose {
		log.Printf("udp relay: start on %s", pc.LocalAddr())
	}

	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }
	// Closing the stream on teardown guarantees the mux→udp goroutine's
	// blocked ReadFull returns. Closing the PacketConn guarantees the
	// udp→mux goroutine's ReadFrom returns. Both are needed because the
	// two goroutines wait on independent sources.
	go func() {
		<-done
		pc.Close()
		st.Close()
	}()

	// Idle-timeout watchdog: if no datagram has flowed in either direction
	// for udpRelayIdleTimeout, force the relay down. Guards against zombie
	// relays accumulating if the client-side teardown ever misses us.
	var lastAct atomic.Int64
	lastAct.Store(time.Now().UnixNano())
	touch := func() { lastAct.Store(time.Now().UnixNano()) }
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				if now.UnixNano()-lastAct.Load() > int64(udpRelayIdleTimeout) {
					closeDone()
					return
				}
			}
		}
	}()

	// mux → udp: read framed packets, send to each declared target.
	go func() {
		defer closeDone()
		for {
			body, err := readFrame(st)
			if err != nil {
				return
			}
			touch()
			targetAddr, data, perr := parseAddrAndData(body)
			if perr != nil {
				continue
			}
			if _, werr := pc.WriteTo(data, targetAddr); werr != nil {
				// Most write errors on an unconnected PacketConn are
				// per-packet — keep the relay alive and drop this one.
				continue
			}
		}
	}()

	// udp → mux: read incoming datagrams from any source, frame with the
	// source address so the client knows who replied.
	go func() {
		defer closeDone()
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			touch()
			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			frame := encodeFrame(udpAddr, buf[:n])
			if frame == nil {
				continue
			}
			if _, werr := st.Write(frame); werr != nil {
				return
			}
		}
	}()

	<-done
}

// readFrame reads a single [LEN:2][BODY] frame from r and returns BODY.
func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	total := binary.BigEndian.Uint16(lenBuf[:])
	if total == 0 {
		return nil, errors.New("udp frame: zero length")
	}
	body := make([]byte, total)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// parseAddrAndData decodes [ATYP:1][ADDR][PORT:2][DATA] into a UDPAddr and
// the payload. For domain ATYP a blocking DNS resolve is performed — this is
// fine in practice because almost nothing sends UDP to a bare domain; DNS,
// QUIC, WireGuard etc. all send to numeric addresses resolved by the client.
func parseAddrAndData(body []byte) (*net.UDPAddr, []byte, error) {
	if len(body) < 1+4+2 {
		return nil, nil, errors.New("short")
	}
	atyp := body[0]
	var ip net.IP
	var host string
	var addrEnd int
	switch atyp {
	case 0x01:
		if len(body) < 1+4+2 {
			return nil, nil, errors.New("short v4")
		}
		ip = net.IP(body[1:5])
		addrEnd = 1 + 4
	case 0x04:
		if len(body) < 1+16+2 {
			return nil, nil, errors.New("short v6")
		}
		ip = net.IP(body[1:17])
		addrEnd = 1 + 16
	case 0x03:
		if len(body) < 2 {
			return nil, nil, errors.New("short domain")
		}
		dLen := int(body[1])
		if len(body) < 2+dLen+2 {
			return nil, nil, errors.New("short domain name")
		}
		host = string(body[2 : 2+dLen])
		addrEnd = 1 + 1 + dLen
	default:
		return nil, nil, fmt.Errorf("bad atyp %d", atyp)
	}
	if len(body) < addrEnd+2 {
		return nil, nil, errors.New("no port")
	}
	port := binary.BigEndian.Uint16(body[addrEnd : addrEnd+2])
	data := body[addrEnd+2:]

	if atyp == 0x03 {
		resolved, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			return nil, nil, err
		}
		return resolved, data, nil
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, data, nil
}

// encodeFrame builds [LEN:2][ATYP:1][ADDR][PORT:2][DATA]. Returns nil if the
// address cannot be represented.
func encodeFrame(addr *net.UDPAddr, data []byte) []byte {
	var atyp byte
	var addrBytes []byte
	if ip4 := addr.IP.To4(); ip4 != nil {
		atyp = 0x01
		addrBytes = ip4
	} else if ip6 := addr.IP.To16(); ip6 != nil {
		atyp = 0x04
		addrBytes = ip6
	} else {
		return nil
	}
	total := 1 + len(addrBytes) + 2 + len(data)
	if total > 0xFFFF {
		return nil
	}
	frame := make([]byte, 2+total)
	binary.BigEndian.PutUint16(frame[0:2], uint16(total))
	frame[2] = atyp
	copy(frame[3:3+len(addrBytes)], addrBytes)
	binary.BigEndian.PutUint16(frame[3+len(addrBytes):5+len(addrBytes)], uint16(addr.Port))
	copy(frame[5+len(addrBytes):], data)
	return frame
}
