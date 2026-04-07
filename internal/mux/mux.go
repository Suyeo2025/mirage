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
	"math"
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
	initialWindow = 256 * 1024       // 256KB initial per-stream receive window
	maxWindow     = math.MaxInt64    // legacy mode: unlimited
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

// OpenStream creates a new local stream. Sends CmdSYN to remote.
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

	// Flow control: send side
	sendWnd   atomic.Int64  // remaining send window (bytes)
	sendWndCh chan struct{} // signaled when window opens up
	flowCtrl  atomic.Bool   // true once we've received at least one CmdWND

	// Flow control: receive side — tracks consumed bytes to send CmdWND back
	recvConsumed atomic.Int64

	// Padding support
	created  time.Time
	pktCount atomic.Int64
}

func newStream(id uint32, sess *Session) *Stream {
	st := &Stream{
		id:        id,
		sess:      sess,
		readBuf:   make(chan []byte, 256), // larger buffer to reduce drops
		sendWndCh: make(chan struct{}, 1),
		created:   time.Now(),
	}
	st.sendWnd.Store(maxWindow) // start unlimited (legacy compat)
	return st
}

func (st *Stream) Read(p []byte) (int, error) {
	for {
		// Drain current buffer first
		if len(st.cur) > 0 {
			n := copy(p, st.cur)
			st.cur = st.cur[n:]

			// Track consumed bytes for flow control.
			// Use atomic add; send window update when threshold reached.
			if st.flowCtrl.Load() {
				consumed := st.recvConsumed.Add(int64(n))
				if consumed >= initialWindow/4 {
					// Reset counter atomically — if another reader already reset,
					// this will go negative briefly but self-corrects.
					st.recvConsumed.Store(0)
					st.sess.sendWindowUpdate(st.id, consumed)
				}
			}

			return n, nil
		}

		// Wait for next chunk
		chunk, ok := <-st.readBuf
		if !ok || chunk == nil {
			return 0, io.EOF
		}
		st.cur = chunk
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

		// Flow control: wait for send window if credit-based mode is active
		if st.flowCtrl.Load() {
			for st.sendWnd.Load() < int64(len(chunk)) {
				// Block until window opens
				<-st.sendWndCh
				if st.closed.Load() {
					return total, io.ErrClosedPipe
				}
			}
			st.sendWnd.Add(-int64(len(chunk)))
		}

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
	// Unblock ALL writers waiting on send window (loop to drain)
	for {
		select {
		case st.sendWndCh <- struct{}{}:
		default:
			return nil
		}
	}
}

func (st *Stream) pushData(data []byte) {
	select {
	case st.readBuf <- data:
	default:
		// Buffer full — block briefly then drop if still full.
		// This is better than the old silent drop but still prevents deadlock.
		select {
		case st.readBuf <- data:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (st *Stream) pushEOF() {
	close(st.readBuf)
}

func (st *Stream) addSendWindow(delta int64) {
	// First CmdWND activates credit-based flow control
	if !st.flowCtrl.Load() {
		st.flowCtrl.Store(true)
		st.sendWnd.Store(0) // reset from maxWindow to credit-based
	}
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
