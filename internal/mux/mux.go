// Package mux provides a simple stream multiplexer that runs inside HTTP bodies.
// Unlike the QUIC-in-HTTP approach, this adds zero ACK overhead — the outer
// HTTP/2+TCP already provides reliable, ordered delivery.
//
// Frame format: [cmd:1][streamID:4][length:2][data:...]
// Total overhead: 7 bytes per frame (same as AnyTLS).
package mux

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
)

const (
	CmdSYN  = 1 // open stream
	CmdPSH  = 2 // data push
	CmdFIN  = 3 // close stream
)

const headerSize = 7 // cmd(1) + streamID(4) + length(2)

// Session multiplexes streams over a bidirectional byte stream (the carrier).
type Session struct {
	writeMu sync.Mutex
	writer  io.Writer

	mu      sync.RWMutex
	streams map[uint32]*Stream
	nextID  atomic.Uint32
	closed  chan struct{}

	// Server side: called when remote opens a new stream
	OnStream func(s *Stream)
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
			st := newStream(streamID, s)
			s.mu.Lock()
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
}

func newStream(id uint32, sess *Session) *Stream {
	return &Stream{
		id:      id,
		sess:    sess,
		readBuf: make(chan []byte, 64),
	}
}

func (st *Stream) Read(p []byte) (int, error) {
	for {
		// Drain current buffer first
		if len(st.cur) > 0 {
			n := copy(p, st.cur)
			st.cur = st.cur[n:]
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
	// Split into 64KB chunks (max frame data size is 65535)
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 65535 {
			chunk = p[:65535]
		}
		if err := st.sess.writeFrame(CmdPSH, st.id, chunk); err != nil {
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
	return nil
}

func (st *Stream) pushData(data []byte) {
	select {
	case st.readBuf <- data:
	default:
		log.Printf("mux: stream %d buffer full, dropping", st.id)
	}
}

func (st *Stream) pushEOF() {
	close(st.readBuf)
}

func (st *Stream) ID() uint32 { return st.id }
