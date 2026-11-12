package proxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestPublicUpstreamIP(t *testing.T) {
	for _, address := range []string{
		"0.1.2.3", "10.0.0.1", "100.100.100.200", "127.0.0.1", "169.254.169.254",
		"172.31.0.1", "192.168.1.1", "198.19.0.1", "224.0.0.1", "240.0.0.1",
		"::", "::1", "::ffff:127.0.0.1", "::ffff:192.168.1.1", "fe80::1", "fd00::1",
		"64:ff9b::7f00:1", "2002:7f00:1::1", "2001:db8::1", "2606:4700::1%eth0",
	} {
		if isPublicUpstreamIP(netip.MustParseAddr(address)) {
			t.Errorf("non-public address allowed: %s", address)
		}
	}
	for _, address := range []string{"8.8.8.8", "::ffff:8.8.8.8", "2606:4700:4700::1111"} {
		if !isPublicUpstreamIP(netip.MustParseAddr(address)) {
			t.Errorf("public address blocked: %s", address)
		}
	}
}

func TestProxyBlocksInternalUpstreams(t *testing.T) {
	server, err := New(Config{Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveTestProxy(t, server)
	for _, tt := range []struct{ method, target, host string }{
		{"GET", "http://127.0.0.1:80/", "127.0.0.1:80"},
		{"GET", "/", "192.168.1.1"},
		{"GET", "https://localhost:443/", "localhost:443"},
		{"CONNECT", "[::ffff:127.0.0.1]:443", "[::ffff:127.0.0.1]:443"},
		{"CONNECT", "localhost:443", "localhost:443"},
	} {
		t.Run(tt.method+" "+tt.target, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			mustWrite(t, conn, []byte(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", tt.method, tt.target, tt.host)))
			resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: tt.method})
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
		})
	}

	for _, target := range [][]byte{
		{socksAtypIPv4, 169, 254, 169, 254},
		append([]byte{socksAtypDomain, byte(len("localhost"))}, "localhost"...),
	} {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		mustWrite(t, conn, []byte{socks5Version, 1, socksMethodNoAuth})
		mustRead(t, conn, 2)
		request := append([]byte{socks5Version, socksCmdConnect, 0}, target...)
		mustWrite(t, conn, binary.BigEndian.AppendUint16(request, 80))
		if reply := mustRead(t, conn, 10); reply[1] != socksRepNotAllowed {
			t.Fatalf("SOCKS5 reply = %x, want connection not allowed", reply)
		}
	}
}
