package relay

import (
	"io"
	"sync"
)

// Bidirectional copies data between a and b until either side closes or errors.
func Bidirectional(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 256*1024) // 256KB buffer for throughput
		io.CopyBuffer(b, a, buf)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 256*1024)
		io.CopyBuffer(a, b, buf)
		closeWrite(a)
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
