package mux

import (
	"context"
	"io"
	"sync"
)

// BufPipe is a buffered in-memory pipe. Unlike io.Pipe, writes never block
// (they append to an internal buffer). Reads block only when the buffer is empty.
type BufPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
	ready  chan struct{} // signaled when data becomes available
}

func NewBufPipe() *BufPipe {
	bp := &BufPipe{
		ready: make(chan struct{}, 1),
	}
	bp.cond = sync.NewCond(&bp.mu)
	return bp
}

func (bp *BufPipe) Write(p []byte) (int, error) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if bp.closed {
		return 0, io.ErrClosedPipe
	}
	bp.buf = append(bp.buf, p...)
	bp.cond.Signal()
	// Signal ready channel (non-blocking)
	select {
	case bp.ready <- struct{}{}:
	default:
	}
	return len(p), nil
}

// Ready returns a channel that is signaled when data becomes available.
// Useful for select-based loops (e.g., upstream keepalive).
func (bp *BufPipe) Ready() <-chan struct{} {
	return bp.ready
}

func (bp *BufPipe) Read(p []byte) (int, error) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	for len(bp.buf) == 0 {
		if bp.closed {
			return 0, io.EOF
		}
		bp.cond.Wait()
	}
	n := copy(p, bp.buf)
	bp.buf = bp.buf[n:]
	return n, nil
}

func (bp *BufPipe) Close() error {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.closed = true
	bp.cond.Broadcast()
	// Also signal ready so WaitAndDrainCtx consumers wake up on close.
	select {
	case bp.ready <- struct{}{}:
	default:
	}
	return nil
}

// Len returns current buffer size (for batch decisions).
func (bp *BufPipe) Len() int {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	return len(bp.buf)
}

// Drain reads all available bytes without blocking.
func (bp *BufPipe) Drain() []byte {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if len(bp.buf) == 0 {
		return nil
	}
	out := bp.buf
	bp.buf = nil
	return out
}

// WaitAndDrain blocks until data is available, then drains all of it.
func (bp *BufPipe) WaitAndDrain() ([]byte, error) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	for len(bp.buf) == 0 {
		if bp.closed {
			return nil, io.EOF
		}
		bp.cond.Wait()
	}
	out := bp.buf
	bp.buf = nil
	return out, nil
}

// WaitAndDrainCtx is like WaitAndDrain but returns early when ctx is cancelled.
// On cancel it still makes one last attempt to drain buffered data so callers
// can deliver in-flight bytes before handing off to a successor.
//
// This is used by the server session to let a new GET handler boot out the
// previous one: the old handler's WaitAndDrainCtx returns ctx.Err() and the
// handler exits, allowing the new handler to own the downstream pipe alone.
func (bp *BufPipe) WaitAndDrainCtx(ctx context.Context) ([]byte, error) {
	for {
		bp.mu.Lock()
		if len(bp.buf) > 0 {
			out := bp.buf
			bp.buf = nil
			bp.mu.Unlock()
			return out, nil
		}
		if bp.closed {
			bp.mu.Unlock()
			return nil, io.EOF
		}
		bp.mu.Unlock()

		select {
		case <-bp.ready:
			// Loop and re-check buf / closed.
		case <-ctx.Done():
			// Final drain: grab any bytes that arrived between the last check
			// and the cancel signal so they are not lost on handoff.
			bp.mu.Lock()
			if len(bp.buf) > 0 {
				out := bp.buf
				bp.buf = nil
				bp.mu.Unlock()
				return out, nil
			}
			bp.mu.Unlock()
			return nil, ctx.Err()
		}
	}
}

// Unread puts bytes back at the head of the buffer. Used by callers that
// drained data but failed to deliver it — preserves byte-stream continuity
// rather than silently losing the drained chunk.
//
// Returns false if the pipe is already closed (caller's data is dropped).
func (bp *BufPipe) Unread(p []byte) bool {
	if len(p) == 0 {
		return true
	}
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if bp.closed {
		return false
	}
	// Prepend: allocate a new slice holding p then existing buf.
	merged := make([]byte, len(p)+len(bp.buf))
	copy(merged, p)
	copy(merged[len(p):], bp.buf)
	bp.buf = merged
	bp.cond.Signal()
	select {
	case bp.ready <- struct{}{}:
	default:
	}
	return true
}
