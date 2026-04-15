package relay

import (
	"io"
	"sync"
	"time"
)

// Bidirectional copies data between a and b until either side closes or errors.
//
// When one direction finishes:
//   - If the conn supports CloseWrite (TCP), signals half-close so the other
//     side can finish gracefully.
//   - If not (VMess, WebSocket, etc.), closes the entire connection after a
//     short grace period — these protocols have no half-close, so the only
//     way to unblock the other goroutine is to force-close.
func Bidirectional(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	// done is closed when the first goroutine finishes.
	// The second goroutine uses it to know a grace period has started.
	done := make(chan struct{})
	var doneOnce sync.Once

	go func() {
		defer wg.Done()
		buf := make([]byte, 256*1024)
		io.CopyBuffer(b, a, buf)
		doneOnce.Do(func() { close(done) })
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 256*1024)
		io.CopyBuffer(a, b, buf)
		doneOnce.Do(func() { close(done) })
		closeWrite(a)
	}()

	// When the first direction finishes, give the other side a grace period.
	// For TCP (CloseWrite works), the other side will finish naturally.
	// For non-TCP protocols, force-close after the grace period.
	go func() {
		<-done
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			// Grace period expired — force close both sides to unblock
			a.Close()
			b.Close()
		case <-waitGroupDone(&wg):
			// Both sides finished naturally — nothing to do
		}
	}()

	wg.Wait()
}

type writeCloser interface {
	CloseWrite() error
}

func closeWrite(c io.ReadWriteCloser) {
	if wc, ok := c.(writeCloser); ok {
		wc.CloseWrite()
	} else {
		c.Close()
	}
}

// waitGroupDone returns a channel that closes when wg reaches zero.
func waitGroupDone(wg *sync.WaitGroup) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		wg.Wait()
		close(ch)
	}()
	return ch
}
