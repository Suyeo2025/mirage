package mux

import (
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
