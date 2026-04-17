// Package mux provides a simple stream multiplexer that runs inside HTTP bodies.
// Unlike the QUIC-in-HTTP approach, this adds zero ACK overhead — the outer
// HTTP/2+TCP already provides reliable, ordered delivery.
//
// Frame format: [cmd:1][streamID:4][length:2][data:...]
// Total overhead: 7 bytes per frame (same as AnyTLS).
package mux

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	CmdSYN      = 1 // open stream
	CmdPSH      = 2 // data push
	CmdFIN      = 3 // close stream
	CmdWaste    = 4 // padding (receiver discards)
	CmdSettings = 5 // server→client config push (streamID=0)
	CmdWND      = 6 // window update (flow control)
)

const headerSize = 7 // cmd(1) + streamID(4) + length(2)

const (
	// initialWindow sized for transcontinental BDP: a 100 Mbps link with
	// ~250 ms RTT needs ~3 MB of in-flight bytes to saturate. 2 MiB lets
	// a single bulk stream reach ~64 Mbps without stalling on CmdWND
	// replenishments — measured throughput drops to <600 KB/s with
	// 256 KB windows on the same link.
	initialWindow = 2 * 1024 * 1024
)

// PaddingOracle decides whether to inject padding after a data frame.
type PaddingOracle interface {
	// ShouldPad returns whether to pad and how many bytes, given stream age
	// and the number of data packets sent so far on this stream.
	ShouldPad(streamAge time.Duration, pktIndex int64) (pad bool, size int)

	// SplitPlan returns how to split a data frame for early packets.
	// Returns a slice of target chunk sizes. If nil, send as one frame.
	// For example, [400, 600, 500] means split into 3 chunks with Waste between each.
	// Inspired by AnyTLS's "336-696,c,387-791,c,..." per-packet split syntax.
	SplitPlan(pktIndex int64, dataLen int) []int
}

// Session multiplexes streams over a bidirectional byte stream (the carrier).
type Session struct {
	writeMu sync.Mutex
	writer  io.Writer

	mu      sync.RWMutex
	streams map[uint32]*Stream
	nextID  atomic.Uint32
	closed  chan struct{}

	// PaddingOracle is optional. When set, padding frames are injected after data writes.
	PaddingOracle PaddingOracle

	// Server side: called when remote opens a new stream
	OnStream func(s *Stream)

	// OnSettings is called when a CmdSettings frame is received.
	OnSettings func(data []byte)
}

// NewSession creates a mux session over the given writer (carrier upstream).
// Call RecvLoop with the reader (carrier downstream) in a separate goroutine.
func NewSession(w io.Writer) *Session {
	s := &Session{
		writer:  w,
		streams: make(map[uint32]*Stream),
		closed:  make(chan struct{}),
	}
	return s
}

// OpenStream creates a new local stream. Sends CmdSYN to remote, then
// immediately advertises an initial receive window so the peer is allowed
// to start sending. Without this, the peer would have zero send credit
// (sendWnd=0) and any Write would block forever — proper per-stream flow
// control needs both sides bootstrapped.
func (s *Session) OpenStream() (*Stream, error) {
	id := s.nextID.Add(1)
	st := newStream(id, s)

	s.mu.Lock()
	s.streams[id] = st
	s.mu.Unlock()

	// Send SYN
	if err := s.writeFrame(CmdSYN, id, nil); err != nil {
		return nil, err
	}
	// Bootstrap peer's send credit. The first CmdWND lets the peer send up
	// to initialWindow bytes back to us; subsequent CmdWND frames replenish
	// as we consume them in Stream.Read.
	s.sendWindowUpdate(id, initialWindow)
	return st, nil
}

// SendWaste sends a padding frame that the receiver will discard.
func (s *Session) SendWaste(size int) error {
	if size <= 0 || size > 65535 {
		return nil
	}
	data := make([]byte, size)
	rand.Read(data)
	return s.writeFrame(CmdWaste, 0, data)
}

// SendSettings sends a configuration payload to the remote (server→client).
func (s *Session) SendSettings(data []byte) error {
	return s.writeFrame(CmdSettings, 0, data)
}

// RecvLoop reads frames from the carrier downstream and dispatches to streams.
// Blocks until EOF or error.
func (s *Session) RecvLoop(r io.Reader) error {
	hdr := make([]byte, headerSize)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return err
		}
		cmd := hdr[0]
		streamID := binary.BigEndian.Uint32(hdr[1:5])
		dataLen := binary.BigEndian.Uint16(hdr[5:7])

		var data []byte
		if dataLen > 0 {
			data = make([]byte, dataLen)
			if _, err := io.ReadFull(r, data); err != nil {
				return err
			}
		}

		switch cmd {
		case CmdSYN:
			s.mu.Lock()
			if _, exists := s.streams[streamID]; exists {
				s.mu.Unlock()
				continue // ignore duplicate SYN
			}
			st := newStream(streamID, s)
			s.streams[streamID] = st
			s.mu.Unlock()
			// Symmetric to OpenStream: bootstrap peer's send credit so
			// they can immediately start writing to us.
			s.sendWindowUpdate(streamID, initialWindow)
			if s.OnStream != nil {
				go s.OnStream(st)
			}
		case CmdPSH:
			s.mu.RLock()
			st := s.streams[streamID]
			s.mu.RUnlock()
			if st != nil {
				st.pushData(data)
			}
		case CmdFIN:
			s.mu.Lock()
			st := s.streams[streamID]
			delete(s.streams, streamID)
			s.mu.Unlock()
			if st != nil {
				st.pushEOF()
			}
		case CmdWaste:
			// Padding — discard silently
		case CmdSettings:
			if s.OnSettings != nil {
				s.OnSettings(data)
			}
		case CmdWND:
			s.mu.RLock()
			st := s.streams[streamID]
			s.mu.RUnlock()
			if st != nil && len(data) >= 4 {
				delta := binary.BigEndian.Uint32(data[:4])
				st.addSendWindow(int64(delta))
			}
		default:
			// Unknown cmd — ignore (forward compatible)
		}
	}
}

func (s *Session) writeFrame(cmd byte, streamID uint32, data []byte) error {
	if len(data) > 65535 {
		return errors.New("mux: data too large")
	}
	hdr := make([]byte, headerSize+len(data))
	hdr[0] = cmd
	binary.BigEndian.PutUint32(hdr[1:5], streamID)
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(data)))
	copy(hdr[headerSize:], data)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.writer.Write(hdr)
	return err
}

// writeFrameAndMaybePad writes a CmdPSH frame with optional splitting and padding.
//
// For early packets (where inner TLS ClientHello is likely), the data is split
// into multiple smaller CmdPSH frames with CmdWaste padding between each chunk.
// This destroys the TLS handshake size signature — the same technique AnyTLS uses
// with its "336-696,c,387-791,c,..." syntax, but with Gaussian-distributed sizes.
//
// For steady-state packets, sends as one frame with optional trailing padding.
func (s *Session) writeFrameAndMaybePad(streamID uint32, data []byte, streamAge time.Duration, pktIndex int64) error {
	if s.PaddingOracle == nil {
		return s.writeFrame(CmdPSH, streamID, data)
	}

	// Check if this packet should be split (early packets)
	if plan := s.PaddingOracle.SplitPlan(pktIndex, len(data)); len(plan) > 1 {
		return s.writeSplitFrames(streamID, data, plan, streamAge, pktIndex)
	}

	// Normal path: single frame + optional trailing waste
	if err := s.writeFrame(CmdPSH, streamID, data); err != nil {
		return err
	}
	if shouldPad, padSize := s.PaddingOracle.ShouldPad(streamAge, pktIndex); shouldPad {
		s.SendWaste(padSize)
	}
	return nil
}

// writeSplitFrames splits data into chunks per the plan, interleaving CmdWaste
// padding between each chunk. This breaks the TLS handshake size fingerprint.
func (s *Session) writeSplitFrames(streamID uint32, data []byte, plan []int, streamAge time.Duration, pktIndex int64) error {
	remaining := data
	for i, chunkSize := range plan {
		if len(remaining) == 0 {
			break // "check" semantics: stop if user data exhausted
		}
		if chunkSize > len(remaining) {
			chunkSize = len(remaining)
		}
		chunk := remaining[:chunkSize]
		remaining = remaining[chunkSize:]

		if err := s.writeFrame(CmdPSH, streamID, chunk); err != nil {
			return err
		}

		// Insert Gaussian waste between chunks (not after last)
		if i < len(plan)-1 || len(remaining) > 0 {
			if _, padSize := s.PaddingOracle.ShouldPad(streamAge, pktIndex); padSize > 0 {
				s.SendWaste(padSize)
			}
		}
	}

	// Send any remaining data that exceeded the plan
	if len(remaining) > 0 {
		if err := s.writeFrame(CmdPSH, streamID, remaining); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) sendWindowUpdate(streamID uint32, delta int64) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(delta))
	s.writeFrame(CmdWND, streamID, buf[:])
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *Session) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	s.mu.Lock()
	for _, st := range s.streams {
		st.pushEOF()
	}
	s.streams = make(map[uint32]*Stream)
	s.mu.Unlock()
	return nil
}

// Stream is a single multiplexed bidirectional stream.
type Stream struct {
	id      uint32
	sess    *Session
	readBuf chan []byte // incoming data chunks
	cur     []byte     // current partially-read chunk
	closed  atomic.Bool

	// done is closed exactly once when the stream is torn down (local Close
	// or remote CmdFIN). Used to unblock pushData and Read without having to
	// close readBuf (which would race with a concurrent send and panic).
	done     chan struct{}
	doneOnce sync.Once

	// Flow control is per-stream and credit-based:
	//   sendWnd  = bytes peer says we may send (replenished by CmdWND we get)
	//   recvConsumed = bytes we've consumed since last CmdWND we sent
	// Both sides bootstrap by sending an initial CmdWND(initialWindow) right
	// after CmdSYN, so neither side ever runs without credit. There is no
	// "legacy mode" — old peers without this bootstrap will see their
	// writes block forever (intentional: protocol mismatch is louder than
	// silent corruption).
	sendWnd      atomic.Int64
	sendWndCh    chan struct{}
	recvConsumed atomic.Int64

	// Padding support
	created  time.Time
	pktCount atomic.Int64
}

func newStream(id uint32, sess *Session) *Stream {
	st := &Stream{
		id:        id,
		sess:      sess,
		readBuf:   make(chan []byte, 256),
		done:      make(chan struct{}),
		sendWndCh: make(chan struct{}, 1),
		created:   time.Now(),
	}
	// sendWnd starts at zero; the peer's bootstrap CmdWND (sent by both
	// OpenStream and the CmdSYN handler) is what unlocks the first writes.
	return st
}

// markDone closes the done channel exactly once, unblocking any Read or
// pushData waiters. Safe to call multiple times and safe when st.done is nil
// (supports tests that build Stream literals without newStream).
func (st *Stream) markDone() {
	st.doneOnce.Do(func() {
		if st.done != nil {
			close(st.done)
		}
	})
}

func (st *Stream) Read(p []byte) (int, error) {
	for {
		// Drain current buffer first
		if len(st.cur) > 0 {
			n := copy(p, st.cur)
			st.cur = st.cur[n:]

			// Replenish peer's send credit as we consume. CAS loop so
			// concurrent readers cannot clobber each other's threshold
			// check: each consumer either "wins" the reset and sends the
			// WND update, or sees the reset-below-threshold state and
			// leaves the next window update to whoever crosses next.
			st.recvConsumed.Add(int64(n))
			for {
				cur := st.recvConsumed.Load()
				if cur < initialWindow/4 {
					break
				}
				if st.recvConsumed.CompareAndSwap(cur, 0) {
					st.sess.sendWindowUpdate(st.id, cur)
					break
				}
			}

			return n, nil
		}

		// Wait for next chunk, or for the stream to be torn down.
		select {
		case chunk, ok := <-st.readBuf:
			if !ok || chunk == nil {
				return 0, io.EOF
			}
			st.cur = chunk
		case <-st.done:
			// Stream closed. Deliver any remaining buffered chunk before EOF
			// so that data in flight at close time is not lost.
			select {
			case chunk, ok := <-st.readBuf:
				if ok && chunk != nil {
					st.cur = chunk
					continue
				}
			default:
			}
			return 0, io.EOF
		}
	}
}

func (st *Stream) Write(p []byte) (int, error) {
	if st.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 65535 {
			chunk = p[:65535]
		}

		// Wait for send credit. The peer's CmdWND replenishments unblock
		// us; if the peer never reads, we never get credit and Write
		// blocks here — that is correct backpressure (only this stream
		// stalls, other streams in the same session stay flowing because
		// each has its own sendWnd).
		for st.sendWnd.Load() < int64(len(chunk)) {
			<-st.sendWndCh
			if st.closed.Load() {
				return total, io.ErrClosedPipe
			}
		}
		st.sendWnd.Add(-int64(len(chunk)))

		pktIdx := st.pktCount.Add(1)
		age := time.Since(st.created)
		if err := st.sess.writeFrameAndMaybePad(st.id, chunk, age, pktIdx); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (st *Stream) Close() error {
	if st.closed.Swap(true) {
		return nil
	}
	st.sess.writeFrame(CmdFIN, st.id, nil)
	st.sess.removeStream(st.id)
	// Unblock any paired Read goroutine waiting on readBuf.
	// Without this, relay.Bidirectional's other copy leg hangs forever when
	// the local side closes first — the core reason the server leaked 500+
	// goroutines over a 9-hour uptime.
	st.markDone()
	// Unblock ALL writers waiting on send window (loop to drain)
	for {
		select {
		case st.sendWndCh <- struct{}{}:
		default:
			return nil
		}
	}
}

// pushData delivers one data frame to the local reader. It blocks until the
// reader makes room OR the stream is closed. The previous implementation
// silently dropped data after a 50ms timeout, which caused inner-TLS
// "bad record mac" errors under load because mux is supposed to provide a
// reliable byte stream. Blocking here back-pressures the mux RecvLoop
// (and therefore the HTTP/2 POST body read) instead — which is what the
// outer transport is designed to handle.
func (st *Stream) pushData(data []byte) {
	select {
	case st.readBuf <- data:
	case <-st.done:
		// Stream was torn down while we were trying to deliver. Drop silently
		// — there is no reader left to care.
	}
}

// pushEOF signals end-of-stream to the local reader. Does not close readBuf
// (that would race with concurrent pushData sends and panic); instead closes
// the done channel via markDone, which both Read and pushData select on.
func (st *Stream) pushEOF() {
	st.markDone()
}

func (st *Stream) addSendWindow(delta int64) {
	st.sendWnd.Add(delta)
	// Signal any blocked writer
	select {
	case st.sendWndCh <- struct{}{}:
	default:
	}
}

func (st *Stream) ID() uint32         { return st.id }
func (st *Stream) Age() time.Duration { return time.Since(st.created) }

// --- Decoy Stream Generator ---
// Generates fake streams that mimic real TLS handshake patterns,
// drowning actual inner TLS handshakes in noise.
// Xue et al. (USENIX Security 2024) showed multiplexing reduces
// TLS-in-TLS detection by >70%. Decoy streams amplify this effect.

// StartDecoyGenerator launches a background goroutine that periodically
// opens fake streams with random data resembling TLS handshake sizes.
// Call the returned cancel function to stop it.
func (s *Session) StartDecoyGenerator(interval time.Duration) func() {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	done := make(chan struct{})
	go s.decoyLoop(interval, done)
	return func() { close(done) }
}

func (s *Session) decoyLoop(interval time.Duration, done <-chan struct{}) {
	// TLS handshake size patterns to mimic (ClientHello, ServerHello+Cert, etc.)
	handshakeSizes := []int{517, 127, 2048, 64, 1400, 300}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-s.closed:
			return
		case <-ticker.C:
			s.emitDecoyStream(handshakeSizes)
		}
	}
}

func (s *Session) emitDecoyStream(sizes []int) {
	// Decoy streams use CmdWaste frames exclusively to avoid stream ID collision.
	// From the wire perspective, CmdWaste frames with varying sizes look identical
	// to real data frames — the observer cannot distinguish cmd byte values because
	// the entire mux layer is inside the encrypted HTTP/2 body.
	// The receiver discards all CmdWaste frames silently.

	nFrames := 2 + int(time.Now().UnixNano()%3) // 2-4 frames
	for i := 0; i < nFrames && i < len(sizes); i++ {
		size := sizes[i]
		// Add Gaussian jitter
		jitter := int(float64(size) * 0.2 * (2*float64(time.Now().UnixNano()%1000)/1000 - 1))
		size += jitter
		if size < 1 {
			size = 1
		}
		if size > 65535 {
			size = 65535
		}
		s.SendWaste(size)
	}
}
