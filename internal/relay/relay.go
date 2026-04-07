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
		io.Copy(b, a)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		io.Copy(a, b)
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
