package mux

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

// pipeSession creates a pair of mux sessions connected via io.Pipe.
func pipeSession(t *testing.T) (client, server *Session, cleanup func()) {
	t.Helper()
	// client writes → server reads
	cr, cw := io.Pipe()
	// server writes → client reads
	sr, sw := io.Pipe()

	client = NewSession(cw)
	server = NewSession(sw)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); client.RecvLoop(sr) }()
	go func() { defer wg.Done(); server.RecvLoop(cr) }()

	cleanup = func() {
		client.Close()
		server.Close()
		cw.Close()
		sw.Close()
		cr.Close()
		sr.Close()
		wg.Wait()
	}
	return
}

func TestStreamRoundTrip(t *testing.T) {
	client, server, cleanup := pipeSession(t)
	defer cleanup()

	done := make(chan struct{})
	server.OnStream = func(st *Stream) {
		defer st.Close()
		buf := make([]byte, 1024)
		n, _ := st.Read(buf)
		st.Write(buf[:n]) // echo
		close(done)
	}

	st, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	msg := []byte("hello mirage")
	st.Write(msg)

	resp := make([]byte, 1024)
	n, err := st.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp[:n], msg) {
		t.Fatalf("got %q, want %q", resp[:n], msg)
	}
	<-done
}

func TestCmdWasteIsDiscarded(t *testing.T) {
	client, server, cleanup := pipeSession(t)
	defer cleanup()

	received := make(chan []byte, 1)
	server.OnStream = func(st *Stream) {
		defer st.Close()
		buf := make([]byte, 1024)
		n, _ := st.Read(buf)
		received <- buf[:n]
	}

	// Inject waste before and after real data
	client.SendWaste(128)
	client.SendWaste(256)

	st, _ := client.OpenStream()
	defer st.Close()

	client.SendWaste(64)
	st.Write([]byte("real data"))
	client.SendWaste(512)

	data := <-received
	if string(data) != "real data" {
		t.Fatalf("got %q, want %q", data, "real data")
	}
}

func TestCmdSettingsCallback(t *testing.T) {
	client, server, cleanup := pipeSession(t)
	defer cleanup()
	_ = server // server side not needed for this test

	settingsReceived := make(chan []byte, 1)
	client.OnSettings = func(data []byte) {
		cp := make([]byte, len(data))
		copy(cp, data)
		settingsReceived <- cp
	}

	// Server sends settings to client (via server's writer → client's RecvLoop)
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	server.SendSettings(payload)

	select {
	case got := <-settingsReceived:
		if !bytes.Equal(got, payload) {
			t.Fatalf("got %v, want %v", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for settings")
	}
}

type mockOracle struct {
	called int
}

func (m *mockOracle) ShouldPad(age time.Duration, pktIdx int64) (bool, int) {
	m.called++
	if pktIdx <= 3 {
		return true, 64
	}
	return false, 0
}

func (m *mockOracle) SplitPlan(pktIdx int64, dataLen int) []int {
	if pktIdx <= 2 && dataLen >= 200 {
		return []int{dataLen / 2, dataLen - dataLen/2} // split in half for early
	}
	return nil
}

func TestPaddingOracleInjection(t *testing.T) {
	// Use a raw bytes.Buffer to inspect frames written
	var buf bytes.Buffer
	sess := NewSession(&buf)

	oracle := &mockOracle{}
	sess.PaddingOracle = oracle

	st := &Stream{
		id:        1,
		sess:      sess,
		readBuf:   make(chan []byte, 256),
		sendWndCh: make(chan struct{}, 1),
		created:   time.Now(),
	}
	st.sendWnd.Store(maxWindow)

	// Write data — should trigger padding oracle
	st.Write([]byte("test"))

	if oracle.called == 0 {
		t.Fatal("padding oracle was never called")
	}

	// Verify that CmdWaste frame appears in the output
	data := buf.Bytes()
	foundWaste := false
	pos := 0
	for pos+headerSize <= len(data) {
		cmd := data[pos]
		dataLen := int(data[pos+5])<<8 | int(data[pos+6])
		if cmd == CmdWaste {
			foundWaste = true
		}
		pos += headerSize + dataLen
	}
	if !foundWaste {
		t.Fatal("expected CmdWaste frame in output")
	}
}

func TestBufPipeReady(t *testing.T) {
	bp := NewBufPipe()

	// Ready should not be signaled initially
	select {
	case <-bp.Ready():
		t.Fatal("ready signaled with no data")
	default:
	}

	bp.Write([]byte("data"))

	select {
	case <-bp.Ready():
		// good
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ready not signaled after write")
	}
}

func TestMultipleStreams(t *testing.T) {
	client, server, cleanup := pipeSession(t)
	defer cleanup()

	const numStreams = 10
	var wg sync.WaitGroup
	wg.Add(numStreams)

	server.OnStream = func(st *Stream) {
		defer st.Close()
		defer wg.Done()
		io.Copy(st, st) // echo
	}

	for i := 0; i < numStreams; i++ {
		go func(idx int) {
			st, err := client.OpenStream()
			if err != nil {
				return
			}
			defer st.Close()

			msg := []byte{byte(idx)}
			st.Write(msg)

			buf := make([]byte, 1)
			st.Read(buf)
		}(i)
	}

	wg.Wait()
}
