package proxy

import (
	"io"
	"net"
	"sync/atomic"
	"time"
)

// relay copies bytes in both directions and propagates half-close. clientReader
// contains bytes that may already have been buffered while detecting the
// protocol, so it is used instead of reading from client directly.
func relay(client net.Conn, clientReader io.Reader, upstream net.Conn, halfCloseTimeout, writeTimeout time.Duration) {
	finished := make(chan error, 2)
	started := time.Now()
	var halfClosed atomic.Bool
	var lastWrite atomic.Int64
	progress := func() {
		if halfClosed.Load() {
			lastWrite.Store(int64(time.Since(started)))
		}
	}
	copyDirection := func(dst net.Conn, src io.Reader) {
		_, err := io.Copy(relayWriter{conn: dst, timeout: writeTimeout, progress: progress}, src)
		if err == nil {
			closeWrite(dst)
		}
		finished <- err
	}
	go copyDirection(upstream, clientReader)
	go copyDirection(client, upstream)

	if err := <-finished; err == nil {
		lastWrite.Store(int64(time.Since(started)))
		halfClosed.Store(true)
		timer := time.NewTimer(halfCloseTimeout)
		defer timer.Stop()
	waitForPeer:
		for {
			select {
			case <-finished:
				_ = upstream.Close()
				_ = client.Close()
				return
			case <-timer.C:
				idle := time.Since(started) - time.Duration(lastWrite.Load())
				if idle >= halfCloseTimeout {
					break waitForPeer
				}
				timer.Reset(halfCloseTimeout - idle)
			}
		}
	}
	_ = upstream.Close()
	_ = client.Close()
	<-finished
}

type relayWriter struct {
	conn     net.Conn
	timeout  time.Duration
	progress func()
}

func (w relayWriter) Write(p []byte) (int, error) {
	if err := w.conn.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
		return 0, err
	}
	n, err := w.conn.Write(p)
	_ = w.conn.SetWriteDeadline(time.Time{})
	if n > 0 {
		w.progress()
	}
	return n, err
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
