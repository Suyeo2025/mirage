package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/houden/mirage/internal/mux"
)

// udpMarker is the target prefix that tells the server this mux stream
// carries framed UDP datagrams instead of a raw TCP byte stream. Must match
// on both sides; anything beyond the ":" is currently unused.
const udpMarker = "udp:"

// handleUDPAssociate fulfils a SOCKS5 UDP ASSOCIATE request (RFC 1928 §6).
//
// Flow:
//  1. Bind a local UDP port and tell the SOCKS5 client to send datagrams there.
//  2. Open a mux stream with the "udp:" target marker so the server knows to
//     switch into UDP relay mode.
//  3. Shuttle datagrams between the local UDP port and the mux stream using
//     our compact wire format: [len:2][atyp:1][addr][port:2][data].
//  4. When the SOCKS5 control TCP connection closes, tear everything down —
//     the TCP conn's lifetime is what defines the UDP association.
func (c *Client) handleUDPAssociate(sess *mux.Session, conn net.Conn) error {
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return fmt.Errorf("udp bind: %w", err)
	}
	defer udpLn.Close()

	// Report the relay endpoint back on the SOCKS5 control connection.
	// Use the TCP conn's local IP so the client can reach us via the same
	// address it already used.
	localTCP, _ := conn.LocalAddr().(*net.TCPAddr)
	var bindIP net.IP
	if localTCP != nil {
		bindIP = localTCP.IP
	}
	if bindIP == nil || bindIP.IsUnspecified() {
		bindIP = net.IPv4(127, 0, 0, 1)
	}
	bindPort := uint16(udpLn.LocalAddr().(*net.UDPAddr).Port)
	if _, err := conn.Write(socks5Reply(0x00, bindIP, bindPort)); err != nil {
		return err
	}

	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	// First 2 bytes + target: "udp:" marker.
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(udpMarker)))
	if _, err := stream.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := stream.Write([]byte(udpMarker)); err != nil {
		return err
	}

	// SOCKS5 UDP associations are anchored to the first observed source addr.
	// Subsequent datagrams from other sources are ignored (RFC §6, implicit).
	var clientAddr *net.UDPAddr
	var clientAddrMu sync.Mutex

	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }

	// The TCP control connection is the association's lifetime. When the
	// app closes it we tear the UDP side down so both ends stop leaking
	// goroutines and sockets.
	go func() {
		io.Copy(io.Discard, conn)
		closeDone()
	}()

	// UDP listener → mux stream.
	go func() {
		defer closeDone()
		buf := make([]byte, 65535)
		for {
			n, srcAddr, err := udpLn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			clientAddrMu.Lock()
			if clientAddr == nil {
				clientAddr = srcAddr
			}
			// Drop packets from any other source to match SOCKS5 semantics.
			registered := clientAddr.IP.Equal(srcAddr.IP) && clientAddr.Port == srcAddr.Port
			clientAddrMu.Unlock()
			if !registered {
				continue
			}
			frame, ok := socks5UDPToMux(buf[:n])
			if !ok {
				continue
			}
			if _, err := stream.Write(frame); err != nil {
				return
			}
		}
	}()

	// Mux stream → UDP listener.
	go func() {
		defer closeDone()
		for {
			body, err := readUDPFrame(stream)
			if err != nil {
				return
			}
			clientAddrMu.Lock()
			ca := clientAddr
			clientAddrMu.Unlock()
			if ca == nil {
				// Haven't seen the app's UDP source yet — can't reply
				continue
			}
			s5 := muxToSocks5UDP(body)
			if s5 == nil {
				continue
			}
			_, _ = udpLn.WriteToUDP(s5, ca)
		}
	}()

	<-done
	return nil
}

// socks5Reply builds a SOCKS5 reply datagram with the given bind endpoint.
func socks5Reply(rep byte, bindIP net.IP, bindPort uint16) []byte {
	if ip4 := bindIP.To4(); ip4 != nil {
		out := make([]byte, 4+4+2)
		out[0] = 0x05
		out[1] = rep
		out[2] = 0x00
		out[3] = 0x01
		copy(out[4:8], ip4)
		binary.BigEndian.PutUint16(out[8:10], bindPort)
		return out
	}
	out := make([]byte, 4+16+2)
	out[0] = 0x05
	out[1] = rep
	out[2] = 0x00
	out[3] = 0x04
	copy(out[4:20], bindIP.To16())
	binary.BigEndian.PutUint16(out[20:22], bindPort)
	return out
}

// socks5UDPToMux converts a SOCKS5 UDP packet (as the app sends it to the
// relay) into our compact mux-stream frame.
//
// SOCKS5 in:  [RSV:2][FRAG:1][ATYP:1][ADDR][PORT:2][DATA]
// Mux out:    [LEN:2][ATYP:1][ADDR][PORT:2][DATA]
//
// Returns nil, false on malformed input or non-zero FRAG (we don't support
// SOCKS5 UDP fragmentation — almost no client uses it).
func socks5UDPToMux(p []byte) ([]byte, bool) {
	if len(p) < 4 {
		return nil, false
	}
	if p[2] != 0 {
		return nil, false // fragmented
	}
	atyp := p[3]
	addrStart := 4
	var addrEnd int
	switch atyp {
	case 0x01:
		addrEnd = addrStart + 4
	case 0x04:
		addrEnd = addrStart + 16
	case 0x03:
		if len(p) < addrStart+1 {
			return nil, false
		}
		addrEnd = addrStart + 1 + int(p[addrStart])
	default:
		return nil, false
	}
	if len(p) < addrEnd+2 {
		return nil, false
	}
	body := p[3:] // atyp + addr + port + data
	if len(body) > 0xFFFF {
		return nil, false
	}
	frame := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(body)))
	copy(frame[2:], body)
	return frame, true
}

// muxToSocks5UDP is the inverse of socks5UDPToMux.
//
// Mux in:    [ATYP:1][ADDR][PORT:2][DATA]    (caller strips the LEN prefix)
// SOCKS5 out:[RSV:2][FRAG:1][ATYP:1][ADDR][PORT:2][DATA]
func muxToSocks5UDP(body []byte) []byte {
	if len(body) < 1+4+2 {
		return nil
	}
	out := make([]byte, 3+len(body))
	out[0], out[1], out[2] = 0, 0, 0 // RSV + FRAG
	copy(out[3:], body)
	return out
}

// readUDPFrame reads one [LEN:2][BODY] frame from r and returns BODY.
func readUDPFrame(r io.Reader) ([]byte, error) {
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

