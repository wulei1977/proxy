package proxy

import (
	"bufio"
	"bytes"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
)

const maxUpstreamHeaderBytes = 10 << 20

// http1Conn observes response heads before net/http removes Connection when
// it sees the close token. The original bytes still go to the transport.
type http1Conn struct {
	net.Conn
	mu      sync.Mutex
	capture *http1HeaderCapture
}

func (c *http1Conn) startHeaderCapture() *http1HeaderCapture {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.capture = &http1HeaderCapture{}
	return c.capture
}

func (c *http1Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if n > 0 && c.capture != nil && c.capture.read(p[:n]) {
		c.capture = nil
	}
	return n, err
}

type http1ResponseHead struct {
	status     int
	protocol   string
	connection []string
}

type http1HeaderCapture struct {
	mu        sync.Mutex
	pending   []byte
	lineStart int
	heads     []http1ResponseHead
}

// read returns true once the final response head has been seen.
func (c *http1HeaderCapture) read(data []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(data) > 0 {
		end := bytes.IndexByte(data, '\n')
		if end < 0 {
			end = len(data) - 1
		}
		line := data[:end+1]
		data = data[end+1:]
		if len(c.pending)+len(line) > maxUpstreamHeaderBytes {
			c.pending = nil
			return true // The transport rejects an oversized head.
		}
		c.pending = append(c.pending, line...)
		if line[len(line)-1] != '\n' {
			continue
		}
		if len(bytes.TrimRight(c.pending[c.lineStart:], "\r\n")) != 0 {
			c.lineStart = len(c.pending)
			continue
		}

		reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(c.pending)))
		statusLine, err := reader.ReadLine()
		if err != nil {
			return true
		}
		fields := strings.Fields(statusLine)
		if len(fields) < 2 {
			return true
		}
		status, err := strconv.Atoi(fields[1])
		if err != nil {
			return true
		}
		header, err := reader.ReadMIMEHeader()
		if err != nil {
			return true
		}
		c.heads = append(c.heads, http1ResponseHead{
			status:     status,
			protocol:   strings.TrimPrefix(fields[0], "HTTP/"),
			connection: header.Values("Connection"),
		})
		c.pending = nil
		c.lineStart = 0
		if status >= 200 || status == 101 {
			return true
		}
	}
	return false
}

func (c *http1HeaderCapture) next() http1ResponseHead {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.heads) == 0 {
		return http1ResponseHead{}
	}
	head := c.heads[0]
	c.heads = c.heads[1:]
	return head
}
