package mux

import (
	"context"
	"errors"
	"io"
	"sync"
)

// maxReplayBytes caps the unacked buffer per direction. When full, Write
// blocks until the peer acks some bytes (or the pipe closes). 4 MiB is a
// generous window — even at 100 Mbps that's >300 ms of RTT slack, which is
// more than any keepalive / ack interval.
const maxReplayBytes = 4 * 1024 * 1024

var (
	errReplayBehindBase   = errors.New("replay: offset behind base (already acked)")
	errReplayAheadOfWrite = errors.New("replay: offset ahead of write")
)

// ReplayPipe is an offset-tracking buffered pipe. Writers append to a
// monotonically growing byte stream; readers pull bytes from a given
// absolute offset without consuming them; peer ACKs trim the buffer at
// the base. This is what makes the mux stream robust across HTTP carrier
// resets — a new HTTP request can resume the byte stream exactly at the
// offset the peer reports having received, instead of losing or
// duplicating bytes.
//
// Invariants:
//
//	baseOff <= offset <= writeOff   for any valid reader offset
//	writeOff - baseOff == len(buf)
type ReplayPipe struct {
	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	baseOff  uint64
	writeOff uint64
	closed   bool
	ready    chan struct{}
}

func NewReplayPipe() *ReplayPipe {
	rp := &ReplayPipe{ready: make(chan struct{}, 1)}
	rp.cond = sync.NewCond(&rp.mu)
	return rp
}

// Write appends bytes, advancing writeOff. Blocks if the unacked buffer
// would exceed maxReplayBytes — natural backpressure on the mux writer
// when the peer is behind on ACKs. Returns io.ErrClosedPipe on close.
func (rp *ReplayPipe) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	rp.mu.Lock()
	defer rp.mu.Unlock()
	for !rp.closed && len(rp.buf)+len(p) > maxReplayBytes {
		rp.cond.Wait()
	}
	if rp.closed {
		return 0, io.ErrClosedPipe
	}
	rp.buf = append(rp.buf, p...)
	rp.writeOff += uint64(len(p))
	rp.cond.Broadcast()
	select {
	case rp.ready <- struct{}{}:
	default:
	}
	return len(p), nil
}

// ReadFromBlock returns a copy of bytes in [offset, writeOff). Blocks until
// that slice is non-empty, ctx cancels, or the pipe closes. On ctx cancel
// it does a best-effort final read so in-flight bytes are not lost on
// handoff between carriers.
func (rp *ReplayPipe) ReadFromBlock(ctx context.Context, offset uint64) ([]byte, error) {
	for {
		rp.mu.Lock()
		if offset < rp.baseOff {
			rp.mu.Unlock()
			return nil, errReplayBehindBase
		}
		if offset > rp.writeOff {
			rp.mu.Unlock()
			return nil, errReplayAheadOfWrite
		}
		if offset < rp.writeOff {
			out := snapshotLocked(rp, offset)
			rp.mu.Unlock()
			return out, nil
		}
		if rp.closed {
			rp.mu.Unlock()
			return nil, io.EOF
		}
		rp.mu.Unlock()

		select {
		case <-rp.ready:
		case <-ctx.Done():
			rp.mu.Lock()
			if offset < rp.writeOff {
				out := snapshotLocked(rp, offset)
				rp.mu.Unlock()
				return out, nil
			}
			rp.mu.Unlock()
			return nil, ctx.Err()
		}
	}
}

// Snapshot returns a copy of bytes in [offset, writeOff) without blocking.
// Returns nil if offset == writeOff or the offset is out of range.
func (rp *ReplayPipe) Snapshot(offset uint64) []byte {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if offset < rp.baseOff || offset >= rp.writeOff {
		return nil
	}
	return snapshotLocked(rp, offset)
}

func snapshotLocked(rp *ReplayPipe, offset uint64) []byte {
	start := int(offset - rp.baseOff)
	out := make([]byte, len(rp.buf)-start)
	copy(out, rp.buf[start:])
	return out
}

// Ack trims bytes up to (but not including) offset. Advances baseOff.
// Offsets <= current baseOff are ignored (stale). Offsets > writeOff are
// clamped.
func (rp *ReplayPipe) Ack(offset uint64) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if offset <= rp.baseOff {
		return
	}
	if offset > rp.writeOff {
		offset = rp.writeOff
	}
	delta := int(offset - rp.baseOff)
	if delta >= len(rp.buf) {
		rp.buf = rp.buf[:0]
	} else {
		// Shift left to reclaim capacity over time.
		rp.buf = append(rp.buf[:0], rp.buf[delta:]...)
	}
	rp.baseOff = offset
	// Wake any writer waiting for buffer space.
	rp.cond.Broadcast()
}

// WriteOffset returns the current absolute write position (total bytes ever
// written).
func (rp *ReplayPipe) WriteOffset() uint64 {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return rp.writeOff
}

// BaseOffset returns the oldest still-buffered byte's offset.
func (rp *ReplayPipe) BaseOffset() uint64 {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return rp.baseOff
}

// Close aborts any pending Write or ReadFromBlock call.
func (rp *ReplayPipe) Close() error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.closed = true
	rp.cond.Broadcast()
	select {
	case rp.ready <- struct{}{}:
	default:
	}
	return nil
}
