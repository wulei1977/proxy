package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTPProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Proxy-Authorization"); got != "" {
			t.Errorf("proxy credentials leaked to origin: %q", got)
		}
		if got := r.Header.Get("Proxy-Connection"); got != "" {
			t.Errorf("hop-by-hop header leaked to origin: %q", got)
		}
		w.Header().Set("X-Upstream", "yes")
		_, _ = io.WriteString(w, "hello "+r.URL.Path)
	}))
	defer upstream.Close()

	proxyAddr := startTestProxy(t, Config{})
	client := proxyClient(t, "http://"+proxyAddr, nil)

	resp, err := client.Get(upstream.URL + "/world?q=1")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Upstream"); got != "yes" {
		t.Fatalf("X-Upstream = %q, want yes", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), "hello /world"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestHTTPProxyRejectsInvalidTargetsBeforeDialing(t *testing.T) {
	server, err := New(Config{Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	dialed := make(chan struct{}, 1)
	server.transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		select {
		case dialed <- struct{}{}:
		default:
		}
		return nil, errors.New("unexpected dial")
	}
	addr := serveTestProxy(t, server)
	for _, tt := range []struct{ name, target, host string }{
		{"userinfo", "http://user:test-only@127.0.0.1:8081/", "127.0.0.1:8081"},
		{"empty userinfo", "http://@127.0.0.1:8081/", "127.0.0.1:8081"},
		{"out-of-range port", "http://127.0.0.1:65536/", "127.0.0.1:65536"},
		{"port zero", "http://127.0.0.1:0/", "127.0.0.1:0"},
		{"out-of-range Host port", "/", "127.0.0.1:65536"},
		{"nonnumeric Host port", "/", "127.0.0.1:not-a-port"},
		{"stray bracket after Host port", "/", "127.0.0.1:65536]"},
		{"invalid Host escape", "/", "invalid%zz.invalid"},
		{"invalid Host escape with port", "/", "invalid%zz.invalid:80"},
		{"missing IPv6 closing bracket", "/", "[::1:80"},
		{"bracketed non-IP host", "/", "[localhost]:80"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			mustWrite(t, conn, []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", tt.target, tt.host)))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
	select {
	case <-dialed:
		t.Fatal("proxy dialed an invalid target")
	default:
	}
}

func TestHTTPAuthorityAllowsDefaultPortsAndIPv6(t *testing.T) {
	for _, authority := range []string{"example.com", "example.com:", "[::1]", "[::1]:", "[fe80::1%eth0]:443"} {
		if !validHTTPAuthority(authority) {
			t.Errorf("valid HTTP authority rejected: %q", authority)
		}
	}
}

func TestHTTPProxyEscapesTargetAndErrorInLogs(t *testing.T) {
	output := make(testLogOutput, 8)
	server, err := New(Config{Logger: log.New(output, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	server.transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial failure\u2028FORGED_ERROR\nSECOND_LINE")
	}
	addr := serveTestProxy(t, server)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	mustWrite(t, conn, []byte("GET http://bad\u2028FORGED_TARGET:80/ HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case line := <-output:
			if !strings.Contains(line, "HTTP GET") {
				continue
			}
			if strings.Count(line, "\n") != 1 || strings.ContainsRune(line, '\u2028') ||
				!strings.Contains(line, `\u2028FORGED_TARGET`) || !strings.Contains(line, `\u2028FORGED_ERROR\nSECOND_LINE`) {
				t.Fatalf("unexpected HTTP error log: %q", line)
			}
			return
		case <-deadline:
			t.Fatal("missing HTTP error log")
		}
	}
}

func TestProxyRetriesTemporaryAcceptErrors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	server, err := New(Config{Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	server.dialer.ControlContext = nil // The origin fixture listens on loopback.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := serveTestProxyListener(t, server, &temporaryTestListener{Listener: listener, failures: 2})
	client := proxyClient(t, "http://"+addr, nil)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
}

func TestProxyConnectionLimit(t *testing.T) {
	server, err := New(Config{MaxConnections: 1, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})

	connect := func() net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		return conn
	}
	first := connect()
	mustWrite(t, first, []byte{socks5Version, 1, socksMethodNoAuth})
	if reply := mustRead(t, first, 2); reply[1] != socksMethodNoAuth {
		t.Fatalf("unexpected SOCKS5 greeting response: %x", reply)
	}

	excess := connect()
	if n, err := excess.Read(make([]byte, 1)); n != 0 || err == nil || os.IsTimeout(err) {
		t.Fatalf("excess connection was not closed: read %d, %v", n, err)
	}

	_ = first.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(server.clientSlots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("closed connection did not release its slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	httpConn := connect()
	mustWrite(t, httpConn, []byte("OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(httpConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status after releasing slot = %d, want 200", resp.StatusCode)
	}
}

func TestListenAndServeReleasesPortAfterRejectedRestart(t *testing.T) {
	initial, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := initial.Addr().String()
	_ = initial.Close()
	server, err := New(Config{ListenAddr: addr, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.ListenAndServe(ctx); err != nil {
		t.Fatal(err)
	}
	if err := server.ListenAndServe(ctx); err == nil || !strings.Contains(err.Error(), "already serving") {
		t.Fatalf("restart error = %v, want already serving", err)
	}
	rebound, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port remained occupied after rejected restart: %v", err)
	}
	_ = rebound.Close()
}

type temporaryTestListener struct {
	net.Listener
	failures int
}

func (l *temporaryTestListener) Accept() (net.Conn, error) {
	if l.failures > 0 {
		l.failures--
		return nil, temporaryTestAcceptError{}
	}
	return l.Listener.Accept()
}

type temporaryTestAcceptError struct{}

func (temporaryTestAcceptError) Error() string   { return "temporary accept failure" }
func (temporaryTestAcceptError) Timeout() bool   { return false }
func (temporaryTestAcceptError) Temporary() bool { return true }

func TestHTTPProxyKeepsConnectionOptionsPerResponse(t *testing.T) {
	peers := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peers <- r.RemoteAddr
		if r.URL.Path == "/first" {
			w.Header().Set("Connection", "X-First")
		} else {
			w.Header().Set("Connection", "close, X-Second")
		}
		w.Header().Set("X-First", "first")
		w.Header().Set("X-Second", "second")
		w.Header().Set("Via", "1.0 upstream")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	client := proxyClient(t, "http://"+startTestProxy(t, Config{}), nil)

	for _, tt := range []struct{ path, hidden, visible string }{
		{"/first", "X-First", "X-Second"},
		{"/second", "X-Second", "X-First"},
	} {
		resp, err := client.Get(upstream.URL + tt.path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.Header.Get(tt.hidden) != "" || resp.Header.Get(tt.visible) == "" {
			t.Fatalf("unexpected response headers on %s: %v", tt.path, resp.Header)
		}
		via := resp.Header.Values("Via")
		if len(via) != 2 || via[0] != "1.0 upstream" || !strings.HasPrefix(via[1], "1.1 goproxy-") {
			t.Fatalf("unexpected Via on %s: %v", tt.path, via)
		}
	}
	if first, second := <-peers, <-peers; first != second {
		t.Fatalf("upstream connection was not reused: %s, %s", first, second)
	}
}

func TestHTTPProxyRejectsSelfForwarding(t *testing.T) {
	server, err := New(Config{Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	// Bound the number of open connections if loop detection regresses.
	server.transport.MaxConnsPerHost = 2
	server.dialer.ControlContext = nil // Exercise Via loop detection against the loopback fixture.
	addr := serveTestProxy(t, server)

	for _, requestTarget := range []string{"/", "http://" + addr + "/"} {
		t.Run(requestTarget, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			// A client must not be able to make the proxy strip its own
			// loop marker by nominating Via as hop-by-hop.
			mustWrite(t, conn, []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Via\r\n\r\n", requestTarget, addr)))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusLoopDetected {
				t.Fatalf("status = %d, want 508", resp.StatusCode)
			}
		})
	}
}

func TestHTTPProxyTimesOutStalledUpload(t *testing.T) {
	cfg := Config{RequestReadTimeout: 500 * time.Millisecond, UpstreamWriteTimeout: 5 * time.Second}
	t.Run("HTTP/1.1", func(t *testing.T) {
		t.Parallel()
		testStalledUpload(t, false, cfg, http.StatusRequestTimeout)
	})
	t.Run("HTTP/2", func(t *testing.T) {
		t.Parallel()
		testStalledUpload(t, true, cfg, http.StatusRequestTimeout)
	})
}

func TestUpstreamWriteTimeoutInterruptsStalledClientRead(t *testing.T) {
	cfg := Config{RequestReadTimeout: 10 * time.Second, UpstreamWriteTimeout: 300 * time.Millisecond}
	t.Run("HTTP/1.1", func(t *testing.T) {
		t.Parallel()
		testStalledUpload(t, false, cfg, http.StatusGatewayTimeout)
	})
	t.Run("HTTP/2", func(t *testing.T) {
		t.Parallel()
		testStalledUpload(t, true, cfg, http.StatusGatewayTimeout)
	})
}

func testStalledUpload(t *testing.T, http2 bool, cfg Config, wantStatus int) {
	t.Helper()
	upstreamRead := make(chan error, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.ProtoMajor == 2) != http2 {
			t.Errorf("unexpected upstream protocol: %s", r.Proto)
		}
		_, err := io.Copy(io.Discard, r.Body)
		upstreamRead <- err
	}))
	defer upstream.Close()
	var addr string
	if http2 {
		upstream.EnableHTTP2 = true
		upstream.StartTLS()
		addr = startTestProxyForTLSOrigin(t, cfg, upstream)
	} else {
		upstream.Start()
		addr = startTestProxy(t, cfg)
	}
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	mustWrite(t, conn, []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 2\r\n\r\nx", upstream.URL, upstream.Listener.Addr())))

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus || !resp.Close {
		t.Fatalf("stalled upload returned status %d, close %t; want %d and close", resp.StatusCode, resp.Close, wantStatus)
	}
	select {
	case err := <-upstreamRead:
		if err == nil {
			t.Fatal("upstream received a complete upload")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream request was not released")
	}
}

func TestHTTPProxyTimesOutBlockedUpstreamWrite(t *testing.T) {
	origin, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	release := make(chan struct{})
	defer close(release)
	go func() {
		conn, err := origin.AcceptTCP()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadBuffer(4096)
		<-release
	}()

	addr := startTestProxy(t, Config{UpstreamWriteTimeout: 500 * time.Millisecond})
	client := proxyClient(t, "http://"+addr, nil)
	upload := bytes.NewReader(make([]byte, 32<<20))
	resp, err := client.Post("http://"+origin.Addr().String(), "application/octet-stream", upload)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
}

func TestHTTPProxyTimesOutBlockedHTTP2Upload(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream protocol = %s, want HTTP/2", r.Proto)
		}
		// Leave the upload blocked on HTTP/2 stream flow control.
		<-r.Context().Done()
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	addr := startTestProxyForTLSOrigin(t, Config{UpstreamWriteTimeout: 500 * time.Millisecond}, upstream)
	client, req := proxyTLSOriginRequest(t, http.MethodPost, addr, upstream.URL, bytes.NewReader(make([]byte, 8<<20)))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
}

func TestHTTPProxyTimesOutBlockedClientWrite(t *testing.T) {
	originStopped := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const responseSize = 64 << 20
		w.Header().Set("Content-Length", strconv.Itoa(responseSize))
		block := make([]byte, 64<<10)
		for sent := 0; sent < responseSize; sent += len(block) {
			if _, err := w.Write(block); err != nil {
				originStopped <- err
				return
			}
		}
		originStopped <- nil
	}))
	defer upstream.Close()
	addr := startTestProxy(t, Config{ClientWriteTimeout: 500 * time.Millisecond})
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.(*net.TCPConn).SetReadBuffer(4096); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	mustWrite(t, conn, []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.URL, upstream.Listener.Addr())))

	// Leave the response unread until the proxy cancels the upstream stream.
	select {
	case err := <-originStopped:
		if err == nil {
			t.Fatal("origin sent the whole response without hitting backpressure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not release the blocked upstream response")
	}
}

func TestHTTPProxyReturnsEarlyRejectionBeforeUploadFinishes(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 413 Content Too Large\r\nConnection: close\r\nContent-Length: 2\r\n\r\nno")
		if err := buf.Flush(); err != nil {
			t.Error(err)
		}
		<-release
	}))
	defer upstream.Close()
	defer close(release)

	addr := startTestProxy(t, Config{RequestReadTimeout: 5 * time.Second})
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	mustWrite(t, conn, []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 2\r\n\r\nx", upstream.URL, upstream.Listener.Addr())))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !resp.Close || err != nil || string(body) != "no" {
		t.Fatalf("early response = status %d, close %t, body %q, err %v", resp.StatusCode, resp.Close, body, err)
	}
}

func TestHTTPProxyForwardsTrailers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "x" {
			t.Errorf("upstream body = %q, err = %v", body, err)
		}
		if r.Header.Get("Te") != "trailers" || !strings.EqualFold(r.Header.Get("Connection"), "TE") {
			t.Errorf("upstream did not receive trailer negotiation: %v", r.Header)
		}
		if r.Trailer.Get("X-Checksum") != "sent" || r.Trailer.Get("X-Late") != "unannounced" ||
			r.Trailer.Get("Proxy-Authorization") != "" || r.Trailer.Get("X-Hop") != "" {
			t.Errorf("unexpected request trailers: %v", r.Trailer)
		}

		w.Header().Set("Trailer", "X-Checksum, Proxy-Authenticate, Proxy-Authentication-Info, X-Hop")
		w.Header().Set("Proxy-Authentication-Info", `nextnonce="upstream-only"`)
		w.Header().Set("Authentication-Info", `nextnonce="end-to-end"`)
		w.Header().Set("Connection", "close, X-Hop")
		w.Header().Set("X-Hop", "private")
		_, _ = io.WriteString(w, "y")
		w.(http.Flusher).Flush()
		w.Header().Set("X-Checksum", "result")
		w.Header().Set(http.TrailerPrefix+"X-Late", "unannounced")
		w.Header().Set(http.TrailerPrefix+"Proxy-Authenticate", "private")
		w.Header().Set(http.TrailerPrefix+"Proxy-Authentication-Info", `nextnonce="upstream-trailer"`)
		w.Header().Set(http.TrailerPrefix+"X-Hop", "private")
	}))
	defer upstream.Close()

	addr := startTestProxy(t, Config{})
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	mustWrite(t, conn, []byte(fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n"+
			"Trailer: X-Checksum, Proxy-Authorization, X-Hop\r\nConnection: TE, X-Hop\r\nTE: trailers\r\n\r\n"+
			"1\r\nx\r\n0\r\nX-Checksum: sent\r\nX-Late: unannounced\r\n"+
			"Proxy-Authorization: private\r\nX-Hop: private\r\n\r\n", upstream.URL, upstream.Listener.Addr())))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Hop") != "" || resp.Header.Get("Proxy-Authentication-Info") != "" ||
		resp.Header.Get("Authentication-Info") != `nextnonce="end-to-end"` ||
		!strings.HasPrefix(resp.Header.Get("Via"), "1.1 goproxy-") {
		t.Fatalf("unexpected response headers: %v", resp.Header)
	}
	if len(resp.Trailer) != 1 {
		t.Fatalf("announced response trailers = %v, want X-Checksum only", resp.Trailer)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "y" {
		t.Fatalf("response body = %q, err = %v", body, err)
	}
	if resp.Trailer.Get("X-Checksum") != "result" || resp.Trailer.Get("X-Late") != "unannounced" || len(resp.Trailer) != 2 {
		t.Fatalf("unexpected response trailers: %v", resp.Trailer)
	}
}

func TestHTTPProxyForwardsTrailersFromTLSOrigin(t *testing.T) {
	t.Run("HTTP/1.1", func(t *testing.T) { testTLSOriginTrailers(t, false) })
	t.Run("HTTP/2 with Content-Length", func(t *testing.T) { testTLSOriginTrailers(t, true) })
}

func testTLSOriginTrailers(t *testing.T, http2 bool) {
	t.Helper()
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantMajor, wantConnection := 1, "TE"
		if http2 {
			wantMajor, wantConnection = 2, ""
			w.Header().Set("Content-Length", "1")
		} else {
			w.Header().Set("Connection", "close, X-Hop")
			w.Header().Set("X-Hop", "private")
		}
		if r.ProtoMajor != wantMajor || r.Header.Get("Te") != "trailers" ||
			r.Header.Get("Connection") != wantConnection {
			t.Errorf("upstream protocol = %s, TE = %q, Connection = %q", r.Proto, r.Header.Get("Te"), r.Header.Get("Connection"))
		}
		w.Header().Set("Trailer", "X-Checksum")
		_, _ = io.WriteString(w, "x")
		if !http2 {
			w.(http.Flusher).Flush()
		}
		w.Header().Set("X-Checksum", "result")
		w.Header().Set(http.TrailerPrefix+"X-Late", "unannounced")
	}))
	upstream.EnableHTTP2 = http2
	upstream.StartTLS()
	defer upstream.Close()

	addr := startTestProxyForTLSOrigin(t, Config{}, upstream)
	client, req := proxyTLSOriginRequest(t, http.MethodGet, addr, upstream.URL, nil)
	req.Header.Set("Connection", "TE")
	req.Header.Set("Te", "trailers")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	viaVersion := "1.1"
	if http2 {
		viaVersion = "2"
	}
	if resp.Header.Get("X-Hop") != "" || !strings.HasPrefix(resp.Header.Get("Via"), viaVersion+" goproxy-") {
		t.Fatalf("unexpected response headers: %v", resp.Header)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "x" {
		t.Fatalf("response body = %q, err = %v", body, err)
	}
	if resp.Trailer.Get("X-Checksum") != "result" || resp.Trailer.Get("X-Late") != "unannounced" {
		t.Fatalf("unexpected response trailers: %v", resp.Trailer)
	}
}

func TestHTTPProxyPreservesCompressedResponse(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(writer, "payload")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "" {
			t.Errorf("proxy added Accept-Encoding: %q", r.Header.Get("Accept-Encoding"))
		}
		w.Header().Set("Cache-Control", "no-transform")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	}))
	defer upstream.Close()
	client := proxyClient(t, "http://"+startTestProxy(t, Config{}), nil)
	client.Transport.(*http.Transport).DisableCompression = true
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" || !bytes.Equal(body, compressed.Bytes()) {
		t.Fatalf("Content-Encoding = %q, body = %q; want unchanged gzip response", resp.Header.Get("Content-Encoding"), body)
	}
}

func TestHTTPProxyTimesOutWaitingForResponseHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer upstream.Close()

	addr := startTestProxy(t, Config{ResponseHeaderTimeout: 500 * time.Millisecond})
	client := proxyClient(t, "http://"+addr, nil)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
}

func TestHTTPProxyAbortsStalledResponseBody(t *testing.T) {
	for _, version := range []string{"HTTP/1.1", "HTTP/2"} {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()
			released := make(chan struct{})
			stop := make(chan struct{})
			http2 := version == "HTTP/2"
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if (r.ProtoMajor == 2) != http2 {
					t.Errorf("upstream protocol = %s, want %s", r.Proto, version)
				}
				w.Header().Set("Content-Length", "65536")
				_, _ = w.Write(bytes.Repeat([]byte("x"), 32768))
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
					close(released)
				case <-stop:
				}
			}))
			defer upstream.Close()
			defer close(stop)

			cfg := Config{ResponseBodyIdleTimeout: 500 * time.Millisecond}
			var client *http.Client
			var req *http.Request
			if http2 {
				upstream.EnableHTTP2 = true
				upstream.StartTLS()
				addr := startTestProxyForTLSOrigin(t, cfg, upstream)
				client, req = proxyTLSOriginRequest(t, http.MethodGet, addr, upstream.URL, nil)
			} else {
				upstream.Start()
				client = proxyClient(t, "http://"+startTestProxy(t, cfg), nil)
				req, _ = http.NewRequest(http.MethodGet, upstream.URL, nil)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if !errors.Is(err, io.ErrUnexpectedEOF) || len(body) == 0 || len(body) >= 65536 {
				t.Fatalf("read %d bytes, err = %v; want partial body and unexpected EOF", len(body), err)
			}
			select {
			case <-released:
			case <-time.After(2 * time.Second):
				t.Fatal("proxy did not cancel the stalled upstream response")
			}
		})
	}
}

func TestHTTPProxyRejectsUpstreamUpgrade(t *testing.T) {
	upstreamClosed := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
		if err := buf.Flush(); err != nil {
			t.Error(err)
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err = buf.ReadByte()
		upstreamClosed <- err
	}))
	defer upstream.Close()

	client := proxyClient(t, "http://"+startTestProxy(t, Config{}), nil)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	select {
	case err := <-upstreamClosed:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("upstream read = %v, want EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not close the upstream connection")
	}
}

func TestHTTPProxyValidatesUpstreamStatus(t *testing.T) {
	for _, tt := range []struct {
		line   string
		status int
	}{
		{"099 Invalid", http.StatusBadGateway},
		{"600 Invalid", http.StatusBadGateway},
		{"599 Extension", 599},
	} {
		t.Run(tt.line, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, buf, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_, _ = fmt.Fprintf(buf, "HTTP/1.1 %s\r\nContent-Length: 0\r\n\r\n", tt.line)
				if err := buf.Flush(); err != nil {
					t.Error(err)
				}
			}))
			defer upstream.Close()
			client := proxyClient(t, "http://"+startTestProxy(t, Config{}), nil)
			resp, err := client.Get(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.status)
			}
		})
	}
}

func TestHTTPProxyRejectsBareLFInChunkSize(t *testing.T) {
	t.Run("HTTP/1.1 upstream", func(t *testing.T) { testMalformedChunkSize(t, false) })
	t.Run("HTTP/2 upstream", func(t *testing.T) { testMalformedChunkSize(t, true) })
}

func testMalformedChunkSize(t *testing.T, http2 bool) {
	t.Helper()
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.ProtoMajor == 2) != http2 {
			t.Errorf("unexpected upstream protocol: %s", r.Proto)
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Errorf("upstream received malformed chunk payload %q", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	var addr string
	if http2 {
		upstream.EnableHTTP2 = true
		upstream.StartTLS()
		addr = startTestProxyForTLSOrigin(t, Config{}, upstream)
	} else {
		upstream.Start()
		addr = startTestProxy(t, Config{})
	}
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	mustWrite(t, conn, []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n1\nx\r\n0\r\n\r\n", upstream.URL, upstream.Listener.Addr())))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !resp.Close {
		t.Fatalf("malformed request returned status %d, close = %t; want 400 and close", resp.StatusCode, resp.Close)
	}
}

func TestHTTPProxyRejectsHTTP2SwitchingProtocols(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream protocol = %s, want HTTP/2", r.Proto)
		}
		w.WriteHeader(http.StatusSwitchingProtocols)
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	addr := startTestProxyForTLSOrigin(t, Config{}, upstream)
	client, req := proxyTLSOriginRequest(t, http.MethodGet, addr, upstream.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestHTTPProxyRejectsUpstreamHopSpecificChallenges(t *testing.T) {
	const challenge = `Basic realm="origin"`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/proxy-auth":
			w.Header().Set("Proxy-Authenticate", challenge)
			w.WriteHeader(http.StatusProxyAuthRequired)
		case "/upgrade":
			w.Header().Set("Connection", "Upgrade")
			w.Header().Set("Upgrade", "test/1")
			w.WriteHeader(http.StatusUpgradeRequired)
		default:
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer upstream.Close()
	client := proxyClient(t, "http://"+startTestProxy(t, Config{}), nil)
	for _, tt := range []struct {
		path            string
		status          int
		originChallenge string
	}{
		{"/proxy-auth", http.StatusBadGateway, ""},
		{"/upgrade", http.StatusBadGateway, ""},
		{"/origin-auth", http.StatusUnauthorized, challenge},
	} {
		t.Run(tt.path, func(t *testing.T) {
			resp, err := client.Get(upstream.URL + tt.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.status || resp.Header.Get("WWW-Authenticate") != tt.originChallenge ||
				resp.Header.Get("Proxy-Authenticate") != "" || resp.Header.Get("Upgrade") != "" {
				t.Fatalf("unexpected response: %s %v", resp.Status, resp.Header)
			}
		})
	}
}

func TestHTTPProxyForwardsEarlyHintsBeforeContinue(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload; as=style")
		w.Header().Set("Connection", "close, X-Hop")
		w.Header().Set("X-Hop", "private")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		w.Header().Del("Connection")
		w.Header().Del("X-Hop")
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "x" {
			t.Errorf("upstream body = %q, err = %v", body, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	addr := startTestProxy(t, Config{})
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	mustWrite(t, conn, []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n", upstream.URL, upstream.Listener.Addr())))
	reader := bufio.NewReader(conn)
	for _, want := range []int{http.StatusEarlyHints, http.StatusContinue, http.StatusNoContent} {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("status = %d, want %d", resp.StatusCode, want)
		}
		wantLink := ""
		if want == http.StatusEarlyHints {
			wantLink = "</style.css>; rel=preload; as=style"
		}
		if resp.Header.Get("Link") != wantLink || resp.Header.Get("X-Hop") != "" {
			t.Fatalf("unexpected headers in %d: %v", want, resp.Header)
		}
		if want != http.StatusContinue && !strings.HasPrefix(resp.Header.Get("Via"), "1.1 goproxy-") {
			t.Fatalf("missing proxy Via in %d: %v", want, resp.Header)
		}
		if want == http.StatusContinue {
			mustWrite(t, conn, []byte("x"))
		}
	}
}

func TestHTTPProxyMaxForwards(t *testing.T) {
	calls := make(chan string, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls <- r.Method + " " + r.Header.Get("Max-Forwards")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	client := proxyClient(t, "http://"+startTestProxy(t, Config{}), nil)

	for _, tt := range []struct {
		method, value string
		status        int
		forwarded     string
	}{
		{http.MethodOptions, "0", http.StatusNoContent, ""},
		{http.MethodTrace, "0", http.StatusNotImplemented, ""},
		{http.MethodOptions, "1", http.StatusOK, "OPTIONS 0"},
		{http.MethodOptions, "001000", http.StatusOK, "OPTIONS 999"},
		{http.MethodOptions, "18446744073709551616", http.StatusOK, "OPTIONS 18446744073709551615"},
		{http.MethodTrace, "2", http.StatusOK, "TRACE 1"},
		{http.MethodOptions, "-1", http.StatusBadRequest, ""},
		{http.MethodGet, "0", http.StatusOK, "GET 0"},
	} {
		t.Run(tt.method+"/"+tt.value, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, upstream.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Max-Forwards", tt.value)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.status)
			}
			var forwarded string
			select {
			case forwarded = <-calls:
			default:
			}
			if forwarded != tt.forwarded {
				t.Fatalf("forwarded = %q, want %q", forwarded, tt.forwarded)
			}
		})
	}
}

func TestHTTPProxyLocalOptionsDoesNotDrainRequestBody(t *testing.T) {
	addr := startTestProxy(t, Config{RequestReadTimeout: 5 * time.Second})
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	mustWrite(t, conn, []byte("OPTIONS http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\nMax-Forwards: 0\r\nContent-Length: 2\r\n\r\nx"))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || !resp.Close {
		t.Fatalf("status = %d, close = %t; want 204 and close", resp.StatusCode, resp.Close)
	}
}

func TestHTTPProxyForwardsServerWideOptions(t *testing.T) {
	t.Run("HTTP/1.1", func(t *testing.T) { testForwardedOptionsTarget(t, false) })
	t.Run("HTTP/2", func(t *testing.T) { testForwardedOptionsTarget(t, true) })
}

func testForwardedOptionsTarget(t *testing.T, http2 bool) {
	t.Helper()
	seen := make(chan string, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.ProtoMajor == 2) != http2 {
			t.Errorf("unexpected upstream protocol: %s", r.Proto)
		}
		seen <- r.RequestURI
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.Config.DisableGeneralOptionsHandler = true
	defer upstream.Close()
	var addr string
	if http2 {
		upstream.EnableHTTP2 = true
		upstream.StartTLS()
		addr = startTestProxyForTLSOrigin(t, Config{}, upstream)
	} else {
		upstream.Start()
		addr = startTestProxy(t, Config{})
	}

	for _, tt := range []struct{ suffix, want string }{
		{"", "*"},
		{"/", "/"},
		{"?mode=1", "/?mode=1"},
		{"?", "/?"},
	} {
		t.Run(upstream.URL+tt.suffix, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			mustWrite(t, conn, []byte(fmt.Sprintf("OPTIONS %s%s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.URL, tt.suffix, upstream.Listener.Addr())))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", resp.StatusCode)
			}
			select {
			case got := <-seen:
				if got != tt.want {
					t.Fatalf("upstream request target = %q, want %q", got, tt.want)
				}
			default:
				t.Fatal("origin did not handle the OPTIONS request")
			}
		})
	}
}

func TestHTTPProxyAbortsTruncatedResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
		if err := buf.Flush(); err != nil {
			t.Error(err)
		}
	}))
	defer upstream.Close()

	client := proxyClient(t, "http://"+startTestProxy(t, Config{}), nil)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("response = %d, %q, %v; want 200, hello, unexpected EOF", resp.StatusCode, body, err)
	}
}

func TestHTTPProxyFlushesEventStream(t *testing.T) {
	release := make(chan struct{})
	event := "data: hello\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(2*len(event)))
		_, _ = io.WriteString(w, event)
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, event)
	}))
	defer upstream.Close()
	defer close(release)

	client := proxyClient(t, "http://"+startTestProxy(t, Config{}), nil)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := make([]byte, len(event))
	if _, err := io.ReadFull(resp.Body, body); err != nil {
		t.Fatal(err)
	}
	if string(body) != event {
		t.Fatalf("first event = %q, want %q", body, event)
	}
}

func TestHTTPProxyConnect(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("origin request did not use TLS")
		}
		_, _ = io.WriteString(w, "secure response")
	}))
	defer upstream.Close()

	proxyAddr := startTestProxy(t, Config{})
	// InsecureSkipVerify only disables verification of the test origin's
	// self-signed certificate. The proxy's CONNECT tunnel is still exercised.
	client := proxyClient(t, "http://"+proxyAddr, &tls.Config{InsecureSkipVerify: true})

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("HTTPS GET through CONNECT: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got != "secure response" {
		t.Fatalf("body = %q, want secure response", got)
	}
}

func TestHTTPProxyConnectReturnsGatewayTimeoutForDialTimeout(t *testing.T) {
	server, err := New(Config{DialTimeout: 250 * time.Millisecond, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	server.dialer.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	addr := serveTestProxy(t, server)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	mustWrite(t, conn, []byte("CONNECT slow.test.:443 HTTP/1.1\r\nHost: slow.test.:443\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
}

func TestHTTPProxyRejectsMalformedConnectBeforeDialing(t *testing.T) {
	addr := startTestProxy(t, Config{RequestReadTimeout: 5 * time.Second})
	origin, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	target := origin.Addr().String()

	for _, tt := range []struct {
		name, target, extra string
		close               bool
	}{
		{name: "origin form", target: "/debug"},
		{name: "path after authority", target: target + "/debug"},
		{name: "query after authority", target: target + "?"},
		{name: "missing port", target: "127.0.0.1"},
		{name: "fixed-length body", target: target, extra: "Content-Length: 2\r\n\r\nx", close: true},
		{name: "chunked body", target: target, extra: "Transfer-Encoding: chunked\r\n\r\n", close: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			extra := tt.extra
			if extra == "" {
				extra = "\r\n"
			}
			mustWrite(t, conn, []byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s", tt.target, target, extra)))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest || (tt.close && !resp.Close) {
				t.Fatalf("status = %d, close = %t; want 400", resp.StatusCode, resp.Close)
			}
		})
	}
	_ = origin.SetDeadline(time.Now().Add(100 * time.Millisecond))
	conn, err := origin.AcceptTCP()
	if err == nil {
		_ = conn.Close()
		t.Fatal("proxy dialed the upstream for an invalid CONNECT")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestHTTPProxyConnectPreservesBufferedTunnelBytes(t *testing.T) {
	target, _ := startEchoServer(t)
	addr := startTestProxy(t, Config{})
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	mustWrite(t, conn, []byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\nPING", target, target)))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var payload [4]byte
	if _, err := io.ReadFull(reader, payload[:]); err != nil || string(payload[:]) != "PING" {
		t.Fatalf("tunnel read = %q, %v; want PING", payload, err)
	}
}

func TestHTTPSProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "via TLS proxy")
	}))
	defer upstream.Close()

	proxyAddr := startTestProxy(t, Config{})
	client := proxyClient(t, "https://"+proxyAddr, &tls.Config{InsecureSkipVerify: true})

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET through HTTPS proxy: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got != "via TLS proxy" {
		t.Fatalf("body = %q, want via TLS proxy", got)
	}
}

func TestHTTPSProxyConnectWithAuthentication(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "TLS proxy CONNECT")
	}))
	defer upstream.Close()

	proxyAddr := startTestProxy(t, Config{
		Username: "alice",
		Password: "s3cret",
	})
	proxyURL := &url.URL{
		Scheme: "https",
		User:   url.UserPassword("alice", "s3cret"),
		Host:   proxyAddr,
	}
	client := proxyClient(t, proxyURL.String(), &tls.Config{InsecureSkipVerify: true})

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("HTTPS GET through authenticated HTTPS proxy: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got != "TLS proxy CONNECT" {
		t.Fatalf("body = %q, want TLS proxy CONNECT", got)
	}
}

func TestSOCKS5ConnectWithAuthentication(t *testing.T) {
	echoAddr, peerAddresses := startEchoServer(t)
	proxyAddr := startTestProxy(t, Config{
		Username: "alice",
		Password: "s3cret",
	})

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	mustWrite(t, conn, []byte{5, 1, socksMethodUserPassword})
	methodReply := mustRead(t, conn, 2)
	if methodReply[0] != 5 || methodReply[1] != socksMethodUserPassword {
		t.Fatalf("method reply = %v, want [5 2]", methodReply)
	}

	auth := []byte{1, byte(len("alice"))}
	auth = append(auth, "alice"...)
	auth = append(auth, byte(len("s3cret")))
	auth = append(auth, "s3cret"...)
	mustWrite(t, conn, auth)
	authReply := mustRead(t, conn, 2)
	if authReply[0] != 1 || authReply[1] != 0 {
		t.Fatalf("auth reply = %v, want [1 0]", authReply)
	}

	host, portString, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte{5, socksCmdConnect, 0, socksAtypDomain, byte(len(host))}
	request = append(request, host...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	mustWrite(t, conn, append(request, "through socks"...))
	bound := readSOCKSReply(t, conn)
	select {
	case peer := <-peerAddresses:
		if bound != peer {
			t.Fatalf("SOCKS bind address = %s, want %s", bound, peer)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not accept the connection")
	}

	if got := string(mustRead(t, conn, len("through socks"))); got != "through socks" {
		t.Fatalf("echo = %q, want through socks", got)
	}
}

func TestSOCKS5ReportsConnectionRefused(t *testing.T) {
	closed, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()
	addr := startTestProxy(t, Config{})
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	mustWrite(t, conn, []byte{5, 1, socksMethodNoAuth})
	mustRead(t, conn, 2)
	request := []byte{5, socksCmdConnect, 0, socksAtypIPv4, 127, 0, 0, 1}
	mustWrite(t, conn, binary.BigEndian.AppendUint16(request, uint16(port)))
	reply := mustRead(t, conn, 10)
	if reply[1] != socksRepConnectionRefused {
		t.Fatalf("SOCKS reply = %v, want connection refused", reply)
	}
}

func TestSOCKS5MapsDNSNameNotFoundToHostUnreachable(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{IsNotFound: true}}
	if got := socksReplyForDialError(err); got != socksRepHostUnreachable {
		t.Fatalf("reply = %#02x, want host unreachable", got)
	}
}

func TestSOCKS5EscapesControlCharactersInDialLogs(t *testing.T) {
	output := make(testLogOutput, 8)
	server, err := New(Config{Logger: log.New(output, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	server.dialer.Resolver = &net.Resolver{PreferGo: true}
	addr := serveTestProxy(t, server)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	mustWrite(t, conn, []byte{5, 1, socksMethodNoAuth})
	mustRead(t, conn, 2)
	host := "bad\nFORGED_LOG_ENTRY\x1b"
	request := append([]byte{5, socksCmdConnect, 0, socksAtypDomain, byte(len(host))}, host...)
	mustWrite(t, conn, binary.BigEndian.AppendUint16(request, 80))
	reply := mustRead(t, conn, 10)
	if reply[1] == socksRepSucceeded {
		t.Fatal("invalid hostname unexpectedly connected")
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case line := <-output:
			if !strings.Contains(line, "SOCKS5 CONNECT") {
				continue
			}
			if strings.Count(line, "\n") != 1 || strings.ContainsRune(line, '\x1b') ||
				!strings.Contains(line, `\nFORGED_LOG_ENTRY\x1b`) {
				t.Fatalf("dial log contains unescaped control characters: %q", line)
			}
			return
		case <-deadline:
			t.Fatal("missing SOCKS5 dial failure log")
		}
	}
}

type testLogOutput chan string

func (w testLogOutput) Write(p []byte) (int, error) {
	w <- string(p)
	return len(p), nil
}

func TestSOCKS5StopsDialAtHandshakeDeadline(t *testing.T) {
	server, err := New(Config{DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	dnsCanceled := make(chan struct{}, 1)
	server.dialer.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		select {
		case dnsCanceled <- struct{}{}:
		default:
		}
		return nil, ctx.Err()
	}}
	proxyConn, clientConn := net.Pipe()
	defer proxyConn.Close()
	defer clientConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handshakeDeadline := time.Now().Add(500 * time.Millisecond)
	_ = proxyConn.SetDeadline(handshakeDeadline)
	done := make(chan error, 1)
	go func() {
		upstream, err := server.dialSOCKSTarget(ctx, proxyConn, bufio.NewReader(proxyConn), "socks-test.example.:80", handshakeDeadline)
		if upstream != nil {
			_ = upstream.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("dial returned %v, want deadline exceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dial outlived the SOCKS5 handshake deadline")
	}
	select {
	case <-dnsCanceled:
	case <-time.After(time.Second):
		t.Fatal("handshake deadline did not cancel DNS")
	}
}

func TestSOCKS5CancelsPendingDial(t *testing.T) {
	bufferSize := bufio.NewReader(strings.NewReader("")).Size()
	t.Run("server shutdown", func(t *testing.T) { testSOCKSDialCancellation(t, 0, false) })
	t.Run("client disconnect with buffered data", func(t *testing.T) { testSOCKSDialCancellation(t, 10, true) })
	t.Run("client disconnect with a full buffer", func(t *testing.T) { testSOCKSDialCancellation(t, bufferSize, true) })
	t.Run("early data exceeds buffer", func(t *testing.T) { testSOCKSDialCancellation(t, bufferSize+1, false) })
	t.Run("client disconnect with oversized data", func(t *testing.T) { testSOCKSDialCancellation(t, 2*bufferSize, true) })
}

func testSOCKSDialCancellation(t *testing.T, earlyDataSize int, disconnect bool) {
	t.Helper()
	server, err := New(Config{DialTimeout: 30 * time.Second, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	dnsStarted, dnsCanceled := make(chan struct{}), make(chan struct{})
	var startOnce, cancelOnce sync.Once
	resolverCtx, stopResolver := context.WithCancel(context.Background())
	defer stopResolver()
	server.dialer.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		startOnce.Do(func() { close(dnsStarted) })
		select {
		case <-ctx.Done():
			cancelOnce.Do(func() { close(dnsCanceled) })
			return nil, ctx.Err()
		case <-resolverCtx.Done():
			return nil, resolverCtx.Err()
		}
	}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	mustWrite(t, conn, []byte{5, 1, socksMethodNoAuth})
	mustRead(t, conn, 2)
	host := "socks-test.example."
	request := append([]byte{5, socksCmdConnect, 0, socksAtypDomain, byte(len(host))}, host...)
	request = binary.BigEndian.AppendUint16(request, 80)
	mustWrite(t, conn, request)
	select {
	case <-dnsStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS did not start its DNS dial")
	}
	if earlyDataSize > 0 {
		mustWrite(t, conn, bytes.Repeat([]byte("x"), earlyDataSize))
	}
	switch {
	case disconnect:
		_ = conn.Close()
	case earlyDataSize == 0:
		cancel()
	default:
		reply := mustRead(t, conn, 10)
		if reply[1] != socksRepGeneralFailure {
			t.Fatalf("reply = %v, want general failure for oversized early data", reply)
		}
	}
	select {
	case <-dnsCanceled:
	case <-time.After(3 * time.Second):
		t.Fatal("DNS dial was not canceled")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not shut down")
	}
}

func TestHalfClosedTunnelsExpireOnlyAfterInactivity(t *testing.T) {
	for _, protocol := range []string{"SOCKS5", "CONNECT"} {
		protocol := protocol
		t.Run(protocol, func(t *testing.T) {
			t.Parallel()
			const timeout = 700 * time.Millisecond
			server, err := New(Config{TunnelHalfCloseTimeout: timeout, Logger: log.New(io.Discard, "", 0)})
			if err != nil {
				t.Fatal(err)
			}
			server.dialer.ControlContext = nil // The tunnel fixture listens on loopback.
			addr := serveTestProxy(t, server)
			target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			_ = target.SetDeadline(time.Now().Add(3 * time.Second))
			client, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(4 * time.Second))
			reader := bufio.NewReader(client)
			if protocol == "SOCKS5" {
				mustWrite(t, client, []byte{5, 1, socksMethodNoAuth})
				mustRead(t, client, 2)
				request := []byte{5, socksCmdConnect, 0, socksAtypIPv4, 127, 0, 0, 1}
				mustWrite(t, client, binary.BigEndian.AppendUint16(request, uint16(target.Addr().(*net.TCPAddr).Port)))
				readSOCKSReply(t, client)
			} else {
				mustWrite(t, client, []byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.Addr(), target.Addr())))
				resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
				if err != nil || resp.StatusCode != http.StatusOK {
					t.Fatalf("CONNECT response = %v, err = %v", resp, err)
				}
			}
			upstream, err := target.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			_ = upstream.SetDeadline(time.Now().Add(3 * time.Second))
			if err := client.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if _, err := upstream.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("upstream read = %v, want half-close EOF", err)
			}

			// Transfer for longer than the timeout, with no individual idle
			// interval long enough to trigger it.
			for _, want := range []byte("ab") {
				time.Sleep(400 * time.Millisecond)
				mustWrite(t, upstream, []byte{want})
				got, err := reader.ReadByte()
				if err != nil || got != want {
					t.Fatalf("remaining direction read = %q, %v, want %q", got, err, want)
				}
			}
			if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
				t.Fatalf("idle half-closed tunnel read = %v, want EOF", err)
			}
			server.conns.Range(func(_, _ any) bool {
				t.Error("idle tunnel remained tracked after closure")
				return false
			})
		})
	}
}

func TestTunnelReleasesBlockedUpstream(t *testing.T) {
	t.Run("client disconnect", func(t *testing.T) { testBlockedTunnelRelease(t, false) })
	t.Run("server shutdown", func(t *testing.T) { testBlockedTunnelRelease(t, true) })
}

func testBlockedTunnelRelease(t *testing.T, shutdown bool) {
	t.Helper()
	timeout := 100 * time.Millisecond
	if shutdown {
		timeout = 10 * time.Second
	}
	server, err := New(Config{TunnelWriteTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	defer server.shutdown()
	clientConn, clientPeer := net.Pipe()
	defer clientPeer.Close()
	upstreamConn, upstreamPeer := net.Pipe()
	defer upstreamPeer.Close()
	client := server.trackConn(clientConn, false)
	upstream := server.trackConn(upstreamConn, false)
	done := make(chan struct{})
	go func() {
		relay(client, client, upstream, server.cfg.TunnelHalfCloseTimeout, server.cfg.TunnelWriteTimeout)
		close(done)
	}()
	_ = clientPeer.SetWriteDeadline(time.Now().Add(time.Second))
	mustWrite(t, clientPeer, []byte("x"))
	// The upstream peer neither reads the forwarded byte nor sends data.
	if shutdown {
		server.shutdown()
	} else {
		_ = clientPeer.Close()
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay remained blocked on upstream I/O")
	}
	_ = upstreamPeer.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := upstreamPeer.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("upstream read = %v, want EOF", err)
	}
}

func TestAuthenticationConfig(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{name: "disabled"},
		{name: "username only", username: "alice", wantErr: true},
		{name: "password only", password: "secret", wantErr: true},
		{name: "colon in username", username: "alice:ops", password: "secret", wantErr: true},
		{name: "colon in password", username: "alice", password: "ops:secret"},
		{name: "tab in username", username: "alice\t", password: "secret", wantErr: true},
		{name: "DEL in password", username: "alice", password: "secret\x7f", wantErr: true},
		{name: "Unicode credentials", username: "用户", password: "密码"},
		{name: "maximum lengths", username: strings.Repeat("a", 255), password: strings.Repeat("b", 255)},
		{name: "username exceeds byte limit", username: strings.Repeat("é", 128), password: "secret", wantErr: true},
		{name: "password exceeds byte limit", username: "alice", password: strings.Repeat("b", 256), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Config{Username: tt.username, Password: tt.password})
			if (err != nil) != tt.wantErr {
				t.Fatalf("New returned %v, want error = %t", err, tt.wantErr)
			}
		})
	}
}

func TestHTTPProxyAuthentication(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "authenticated")
	}))
	defer upstream.Close()

	proxyAddr := startTestProxy(t, Config{
		Username: "alice",
		Password: "s3cret",
	})

	t.Run("missing credentials", func(t *testing.T) {
		client := proxyClient(t, "http://"+proxyAddr, nil)
		resp, err := client.Get(upstream.URL)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status = %d, want 407", resp.StatusCode)
		}
		if got := resp.Header.Get("Proxy-Authenticate"); !strings.HasPrefix(got, "Basic ") {
			t.Fatalf("Proxy-Authenticate = %q, want Basic challenge", got)
		}
	})

	t.Run("with credentials", func(t *testing.T) {
		proxyURL := &url.URL{
			Scheme: "http",
			User:   url.UserPassword("alice", "s3cret"),
			Host:   proxyAddr,
		}
		client := proxyClient(t, proxyURL.String(), nil)
		resp, err := client.Get(upstream.URL)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})
}

func TestHTTPProxyNormalizesBasicCredentials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	cfg := Config{
		Username: "e\u0301",
		Password: "A\u030a",
		Logger:   log.New(io.Discard, "", 0),
	}
	server, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server.dialer.ControlContext = nil // The origin fixture listens on loopback.
	addr := serveTestProxy(t, server)
	for _, tt := range []struct {
		name, username, password string
		status                   int
	}{
		{"NFC", "é", "Å", http.StatusNoContent},
		{"configured bytes", cfg.Username, cfg.Password, http.StatusNoContent},
		{"wrong password", "é", "different", http.StatusProxyAuthRequired},
	} {
		t.Run(tt.name, func(t *testing.T) {
			proxyURL := &url.URL{Scheme: "http", Host: addr, User: url.UserPassword(tt.username, tt.password)}
			client := proxyClient(t, proxyURL.String(), nil)
			resp, err := client.Get(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.status)
			}
		})
	}
	if !server.auth.checkSOCKS5([]byte(cfg.Username), []byte(cfg.Password)) ||
		server.auth.checkSOCKS5([]byte("é"), []byte("Å")) {
		t.Fatal("SOCKS5 authentication did not preserve byte-exact credentials")
	}
}

func TestHTTPProxyRejectsInvalidUTF8BasicCredentials(t *testing.T) {
	const username = "alice"
	password := string([]byte{'p', 0xff})
	server, err := New(Config{Username: username, Password: password, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if !server.auth.checkSOCKS5([]byte(username), []byte(password)) {
		t.Fatal("SOCKS5 rejected its byte-exact credentials")
	}
	addr := serveTestProxy(t, server)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(username, password)
	mustWrite(t, conn, []byte("OPTIONS * HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: "+
		req.Header.Get("Authorization")+"\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired ||
		!strings.Contains(resp.Header.Get("Proxy-Authenticate"), `charset="UTF-8"`) {
		t.Fatalf("unexpected response: %s %v", resp.Status, resp.Header)
	}
}

func TestBasicAuthenticationPreservesLiteralCombiningGraphemeJoiner(t *testing.T) {
	withoutJoiner := strings.Repeat("\u0301", 31)
	withJoiner := strings.Repeat("\u0301", 30) + "\u034f\u0301"
	lateCedilla := "x" + withoutJoiner + "\u0327"
	earlyCedilla := "x\u0327" + withoutJoiner
	for _, tt := range []struct {
		name, configured, submitted string
		accepted                    bool
	}{
		{"literal joiner matches itself", withJoiner, withJoiner, true},
		{"missing literal joiner", withJoiner, withoutJoiner, false},
		{"extra literal joiner", withoutJoiner, withJoiner, false},
		{"canonical reordering across a long run", lateCedilla, earlyCedilla, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			auth := newAuthenticator("alice", tt.configured)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.SetBasicAuth("alice", tt.submitted)
			req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
			if got := auth.checkHTTP(req); got != tt.accepted {
				t.Fatalf("authentication = %t, want %t", got, tt.accepted)
			}
		})
	}
}

func TestHTTPProxyRejectsUnauthenticatedUploadWithoutDraining(t *testing.T) {
	addr := startTestProxy(t, Config{Username: "alice", Password: "secret", RequestReadTimeout: 5 * time.Second})
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	mustWrite(t, conn, []byte("POST http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\nContent-Length: 2\r\n\r\nx"))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired || !resp.Close || resp.Header.Get("Proxy-Authenticate") == "" {
		t.Fatalf("unexpected authentication response: %d, close %t, headers %v", resp.StatusCode, resp.Close, resp.Header)
	}
}

func TestHTTPProxyAuthenticatesServerWideOptions(t *testing.T) {
	addr := startTestProxy(t, Config{Username: "alice", Password: "secret", RequestReadTimeout: 5 * time.Second})
	for _, tt := range []struct {
		name, extra string
		status      int
	}{
		{name: "missing credentials", extra: "\r\n", status: http.StatusProxyAuthRequired},
		{name: "authenticated", extra: "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n", status: http.StatusOK},
		{name: "authenticated with unread body", extra: "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\nContent-Length: 2\r\n\r\nx", status: http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			mustWrite(t, conn, []byte("OPTIONS * HTTP/1.1\r\nHost: localhost\r\n"+tt.extra))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.status)
			}
			if tt.status == http.StatusProxyAuthRequired && resp.Header.Get("Proxy-Authenticate") == "" {
				t.Fatal("missing Proxy-Authenticate")
			}
			if strings.Contains(tt.extra, "Content-Length") && !resp.Close {
				t.Fatal("connection must close after a local response with an unread request body")
			}
		})
	}
}

func TestHTTPProxyRejectsAsteriskForOtherMethods(t *testing.T) {
	upstreamCalls := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	addr := startTestProxy(t, Config{})
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	mustWrite(t, conn, []byte(fmt.Sprintf("GET * HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.Listener.Addr())))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	select {
	case <-upstreamCalls:
		t.Fatal("proxy forwarded an invalid asterisk request")
	default:
	}
}

func TestNormalizeConnectTarget(t *testing.T) {
	tests := []struct {
		input     string
		want      string
		wantError bool
	}{
		{input: "example.com:8443", want: "example.com:8443"},
		{input: "example.com", wantError: true},
		{input: "127.0.0.1:80", want: "127.0.0.1:80"},
		{input: "[::1]:443", want: "[::1]:443"},
		{input: "[fe80::1%eth0]:443", want: "[fe80::1%eth0]:443"},
		{input: "[::1]", wantError: true},
		{input: "::1", wantError: true},
		{input: "[example.com]:443", wantError: true},
		{input: "", wantError: true},
		{input: "example.com:0", wantError: true},
		{input: "example.com:+443", wantError: true},
		{input: "example.com:70000", wantError: true},
		{input: "user@example.com:443", wantError: true},
		{input: "http://example.com", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := normalizeConnectTarget(tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatalf("normalizeConnectTarget(%q) = %q, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeConnectTarget(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeConnectTarget(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	headers := http.Header{
		"Connection":          {"X-Custom, keep-alive"},
		"X-Custom":            {"remove me"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Authorization": {"Basic abc"},
		"Te":                  {"trailers"},
		"Transfer-Encoding":   {"chunked"},
		"Upgrade":             {"websocket"},
		"Content-Type":        {"text/plain"},
	}
	removeHopByHopHeaders(headers)
	if got := headers.Get("X-Custom"); got != "" {
		t.Fatalf("X-Custom = %q, want removed", got)
	}
	if got := headers.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type = %q, want preserved", got)
	}
}

func startTestProxy(t *testing.T, cfg Config) string {
	t.Helper()

	cfg.ListenAddr = "127.0.0.1:0"
	cfg.DialTimeout = 3 * time.Second
	cfg.Logger = log.New(io.Discard, "", 0)

	server, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server.dialer.ControlContext = nil // The origin fixtures listen on loopback.
	return serveTestProxy(t, server)
}

func startTestProxyForTLSOrigin(t *testing.T, cfg Config, upstream *httptest.Server) string {
	t.Helper()
	cfg.Logger = log.New(io.Discard, "", 0)
	server, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server.dialer.ControlContext = nil // The origin fixture listens on loopback.
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	server.transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	return serveTestProxy(t, server)
}

func proxyTLSOriginRequest(t *testing.T, method, addr, target string, body io.Reader) (*http.Client, *http.Request) {
	t.Helper()
	// Send an absolute HTTPS request target directly. A conventional Go
	// proxy client would use CONNECT and bypass the proxy's HTTP transport.
	req, err := http.NewRequest(method, "http://"+addr, body)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.Opaque = target
	client := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	return client, req
}

func serveTestProxy(t *testing.T, server *Server) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return serveTestProxyListener(t, server, listener)
}

func serveTestProxyListener(t *testing.T, server *Server, listener net.Listener) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx, listener)
	}()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("proxy did not shut down")
		}
	})

	addr := listener.Addr().String()
	waitForListener(t, addr)
	return addr
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("proxy at %s did not start", addr)
}

func proxyClient(t *testing.T, proxyAddress string, tlsConfig *tls.Config) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(proxyAddress)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: tlsConfig,
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}

func startEchoServer(t *testing.T) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})
	peerAddresses := make(chan string, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case peerAddresses <- conn.RemoteAddr().String():
			default:
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String(), peerAddresses
}

func readSOCKSReply(t *testing.T, conn net.Conn) string {
	t.Helper()
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("read SOCKS reply: %v", err)
	}
	if header[0] != 5 || header[1] != 0 {
		t.Fatalf("SOCKS reply = %v, want success", header)
	}
	var addressLength int
	switch header[3] {
	case socksAtypIPv4:
		addressLength = 4
	case socksAtypIPv6:
		addressLength = 16
	default:
		t.Fatalf("unknown address type %d", header[3])
	}
	ip := net.IP(mustRead(t, conn, addressLength))
	port := binary.BigEndian.Uint16(mustRead(t, conn, 2))
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

func mustWrite(t *testing.T, conn net.Conn, data []byte) {
	t.Helper()
	if err := writeAll(conn, data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func mustRead(t *testing.T, conn net.Conn, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatalf("read: %v", err)
	}
	return data
}
