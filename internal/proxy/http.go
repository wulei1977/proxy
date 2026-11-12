package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errUpstreamWriteTimeout = fmt.Errorf("writing request upstream: %w", context.DeadlineExceeded)
	errUpstreamBodyTimeout  = fmt.Errorf("reading upstream response body: %w", context.DeadlineExceeded)
	errUpstreamResponseHead = errors.New("could not inspect upstream HTTP/1 response headers")
	errUpstreamUpgrade      = errors.New("upstream protocol upgrade is not supported")
)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.auth.checkHTTP(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="goproxy", charset="UTF-8"`)
		localHTTPError(w, r, "proxy authentication required", http.StatusProxyAuthRequired)
		if s.cfg.Verbose {
			s.logf("HTTP authentication failed for %s", r.RemoteAddr)
		}
		return
	}

	switch {
	case r.RequestURI == "*":
		if r.Method != http.MethodOptions {
			localHTTPError(w, r, "asterisk request target requires OPTIONS", http.StatusBadRequest)
			return
		}
		closeUnreadRequest(w, r)
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodConnect:
		s.handleConnect(w, r)
	default:
		s.handleHTTP(w, r)
	}
}

func localHTTPError(w http.ResponseWriter, r *http.Request, message string, status int) {
	closeUnreadRequest(w, r)
	http.Error(w, message, status)
}

// closeUnreadRequest is for local responses, before the proxy has read the body.
func closeUnreadRequest(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength != 0 && r.Body != nil {
		w.Header().Set("Connection", "close")
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
	}
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	clientWriter := &clientResponseWriter{
		ResponseWriter: w,
		controller:     http.NewResponseController(w),
		timeout:        s.cfg.ClientWriteTimeout,
	}
	// net/http may flush buffered headers, body, or trailers after we return.
	defer clientWriter.armWriteDeadline()
	w = clientWriter

	// Check before stripping hop-by-hop headers. A request sent to a
	// local alias will carry this instance's Via entry when it comes back.
	for _, value := range r.Header.Values("Via") {
		for _, entry := range strings.Split(value, ",") {
			fields := strings.Fields(entry)
			if len(fields) >= 2 && strings.EqualFold(fields[1], s.viaName) {
				localHTTPError(w, r, "proxy forwarding loop", http.StatusLoopDetected)
				return
			}
		}
	}

	if r.URL == nil {
		localHTTPError(w, r, "bad request", http.StatusBadRequest)
		return
	}

	// Standard proxy requests use absolute-form URLs. Accept origin-form too,
	// using the Host header and a plain HTTP scheme.
	absoluteForm := r.URL.IsAbs()
	if !absoluteForm {
		if r.Host == "" {
			localHTTPError(w, r, "bad request: missing target host", http.StatusBadRequest)
			return
		}
		r.URL.Scheme = "http"
		r.URL.Host = r.Host
	}
	if r.URL.Host == "" {
		localHTTPError(w, r, "bad request: missing target host", http.StatusBadRequest)
		return
	}
	if r.URL.User != nil {
		localHTTPError(w, r, "bad request: target URL cannot contain user information", http.StatusBadRequest)
		return
	}
	if !validHTTPAuthority(r.URL.Host) {
		localHTTPError(w, r, "bad request: invalid target host or port", http.StatusBadRequest)
		return
	}
	scheme := strings.ToLower(r.URL.Scheme)
	if scheme != "http" && scheme != "https" {
		localHTTPError(w, r, "unsupported URL scheme", http.StatusBadRequest)
		return
	}
	logTarget := scheme + "://" + r.URL.Host

	outCtx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	outReq := r.Clone(outCtx)
	outReq.RequestURI = ""
	outReq.Close = false
	outReq.Host = "" // Use the absolute URL's host as the Host header.
	outReq.URL.Scheme = scheme
	if r.Method == http.MethodOptions && absoluteForm && r.URL.Path == "" &&
		r.URL.RawQuery == "" && !r.URL.ForceQuery {
		outReq.URL.Path = "*"
	}
	outReq.Header = r.Header.Clone()
	outReq.Header.Del("Proxy-Authorization")
	removeHopByHopHeaders(outReq.Header)
	outReq.Header.Add("Via", s.viaValue(r.ProtoMajor, r.ProtoMinor))
	if !applyMaxForwards(w, r, outReq) {
		return
	}
	clientWantsTrailers := acceptsTrailers(r.Header)
	if clientWantsTrailers {
		outReq.Header.Set("Te", "trailers")
	}
	var body *forwardedRequestBody
	if r.ContentLength != 0 && r.Body != nil {
		if r.ContentLength == -1 {
			outReq.Trailer = filterTrailers(r.Trailer, r.Header.Values("Connection"))
		}
		body = &forwardedRequestBody{ReadCloser: r.Body, source: r, trailers: outReq.Trailer}
		outReq.Body = body
	}

	onWriteTimeout := func() {
		cancel(errUpstreamWriteTimeout)
		if body != nil && !body.complete.Load() {
			// Canceling the upstream request cannot interrupt a pending client read.
			_ = clientWriter.controller.SetReadDeadline(time.Now())
		}
	}
	resp, err := s.roundTripHTTP(w, outReq, r.Header.Get("Expect") != "", onWriteTimeout)
	if body != nil && !body.complete.Load() {
		// An early final response must reach the client before the server
		// tries to drain the rest of the upload for connection reuse.
		w.Header().Set("Connection", "close")
		defer clientWriter.controller.SetReadDeadline(time.Now())
	}
	if err != nil {
		status := upstreamErrorStatus(err)
		if context.Cause(outCtx) == errUpstreamWriteTimeout {
			err = errUpstreamWriteTimeout
			status = http.StatusGatewayTimeout
		} else if errors.Is(err, errUpstreamAddressDenied) {
			status = http.StatusForbidden
		} else if body != nil {
			if clientStatus := int(body.clientErrorStatus.Load()); clientStatus != 0 {
				status = clientStatus
			}
		}
		http.Error(w, http.StatusText(status), status)
		s.logf("HTTP %s %q failed: %q", r.Method, logTarget, err.Error())
		return
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusSwitchingProtocols, http.StatusUpgradeRequired:
		http.Error(w, errUpstreamUpgrade.Error(), http.StatusBadGateway)
		return
	case http.StatusProxyAuthRequired:
		http.Error(w, "upstream proxy authentication is not supported", http.StatusBadGateway)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode > 599 {
		http.Error(w, "invalid upstream response status", http.StatusBadGateway)
		return
	}

	responseConnection := resp.Header.Values("Connection")
	removeHopByHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.Header().Add("Via", s.viaValue(resp.ProtoMajor, resp.ProtoMinor))
	var announcedTrailers http.Header
	forceChunked := false
	canSendTrailers := r.ProtoAtLeast(1, 1) && r.Method != http.MethodHead &&
		resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusResetContent &&
		resp.StatusCode != http.StatusNotModified
	if canSendTrailers {
		announcedTrailers = filterTrailers(resp.Trailer, responseConnection)
		if len(announcedTrailers) > 0 {
			names := make([]string, 0, len(announcedTrailers))
			for name := range announcedTrailers {
				names = append(names, name)
			}
			slices.Sort(names)
			w.Header().Set("Trailer", strings.Join(names, ", "))
		}
		// HTTP/2 may send trailers even when the body length is known.
		forceChunked = len(announcedTrailers) > 0 || (resp.ProtoMajor >= 2 && clientWantsTrailers)
		if forceChunked {
			w.Header().Del("Content-Length")
		}
	}
	w.WriteHeader(resp.StatusCode)

	var dst io.Writer = w
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediaType == "text/event-stream" || resp.ContentLength == -1 || forceChunked {
		if err := clientWriter.flush(); err != nil {
			panic(http.ErrAbortHandler)
		}
		dst = flushingWriter{Writer: w, flush: clientWriter.flush}
	}
	reader := upstreamBodyReader{Reader: resp.Body, timeout: s.cfg.ResponseBodyIdleTimeout, cancel: cancel}
	if _, err := io.Copy(dst, reader); err != nil {
		if s.cfg.Verbose {
			s.logf("HTTP %s %q response copy failed: %q", r.Method, logTarget, err.Error())
		}
		// The status is already committed. Abort so net/http does not finish
		// an incomplete response with a valid end-of-message marker.
		panic(http.ErrAbortHandler)
	}

	if canSendTrailers && (resp.ContentLength == -1 || forceChunked) {
		trailers := filterTrailers(resp.Trailer, responseConnection)
		for name := range announcedTrailers {
			w.Header()[name] = trailers[name]
			delete(trailers, name)
		}
		for name, values := range trailers {
			w.Header()[http.TrailerPrefix+name] = values
		}
	}

	if s.cfg.Verbose {
		s.logf("HTTP %s %q -> %d", r.Method, logTarget, resp.StatusCode)
	}
}

func upstreamErrorStatus(err error) int {
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

func (s *Server) viaValue(major, minor int) string {
	if major >= 2 {
		return fmt.Sprintf("%d %s", major, s.viaName)
	}
	return fmt.Sprintf("%d.%d %s", major, minor, s.viaName)
}

type forwardedRequestBody struct {
	io.ReadCloser
	source            *http.Request
	trailers          http.Header
	readMu            sync.Mutex
	complete          atomic.Bool
	clientErrorStatus atomic.Int32
}

func (b *forwardedRequestBody) Read(p []byte) (int, error) {
	b.readMu.Lock()
	defer b.readMu.Unlock()
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		// The incoming request only has trailer values after Body reaches EOF.
		// Update the map already held by the outbound transport.
		if b.trailers != nil {
			for name, values := range filterTrailers(b.source.Trailer, b.source.Header.Values("Connection")) {
				b.trailers[name] = values
			}
		}
		b.complete.Store(true)
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		b.clientErrorStatus.Store(http.StatusRequestTimeout)
	} else if err != nil && !errors.Is(err, http.ErrBodyReadAfterClose) &&
		!errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		b.clientErrorStatus.Store(http.StatusBadRequest)
	}
	return n, err
}

func (b *forwardedRequestBody) Close() error {
	err := b.ReadCloser.Close()
	// Transport can return after closing the body on cancellation. Wait
	// for an interrupted read to record its outcome before Close returns.
	b.readMu.Lock()
	b.readMu.Unlock()
	return err
}

type upstreamBodyReader struct {
	io.Reader
	timeout time.Duration
	cancel  context.CancelCauseFunc
}

func (r upstreamBodyReader) Read(p []byte) (int, error) {
	// Cancel only while waiting on upstream I/O. Downstream writes have
	// their own deadline and must not consume this read timeout.
	timer := time.AfterFunc(r.timeout, func() { r.cancel(errUpstreamBodyTimeout) })
	n, err := r.Reader.Read(p)
	if !timer.Stop() {
		r.cancel(errUpstreamBodyTimeout)
		return n, errUpstreamBodyTimeout
	}
	return n, err
}

func acceptsTrailers(header http.Header) bool {
	for _, value := range header.Values("Te") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "trailers") {
				return true
			}
		}
	}
	return false
}

func filterTrailers(trailers http.Header, connection []string) http.Header {
	filtered := make(http.Header, len(trailers))
	for name, values := range trailers {
		switch name {
		case "Authorization", "Cache-Control", "Content-Encoding", "Content-Length",
			"Content-Range", "Content-Type", "Cookie", "Expect", "Host", "Max-Forwards",
			"Pragma", "Range", "Realm", "Set-Cookie", "Via", "Www-Authenticate":
			continue
		}
		if !strings.HasPrefix(name, "If-") {
			filtered[name] = values
		}
	}
	removeHopByHopHeaders(filtered)
	removeConnectionHeaders(filtered, connection)
	return filtered
}

func applyMaxForwards(w http.ResponseWriter, r, outReq *http.Request) bool {
	if r.Method != http.MethodOptions && r.Method != http.MethodTrace {
		return true
	}
	values := r.Header.Values("Max-Forwards")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 || values[0] == "" || strings.Trim(values[0], "0123456789") != "" {
		localHTTPError(w, r, "invalid Max-Forwards", http.StatusBadRequest)
		return false
	}

	if hops := strings.TrimLeft(values[0], "0"); hops != "" {
		// Decrement the decimal string without imposing an integer size limit.
		remaining := []byte(hops)
		last := len(remaining) - 1
		for remaining[last] == '0' {
			remaining[last] = '9'
			last--
		}
		remaining[last]--
		if len(remaining) > 1 && remaining[0] == '0' {
			remaining = remaining[1:]
		}
		outReq.Header.Set("Max-Forwards", string(remaining))
		return true
	}
	if r.Method == http.MethodOptions {
		closeUnreadRequest(w, r)
		w.WriteHeader(http.StatusNoContent)
	} else {
		localHTTPError(w, r, "TRACE is not supported by this proxy", http.StatusNotImplemented)
	}
	return false
}

func (s *Server) roundTripHTTP(w http.ResponseWriter, req *http.Request, expectContinue bool, onWriteTimeout func()) (*http.Response, error) {
	var mu sync.Mutex
	done, sentContinue := false, false
	var capture *http1HeaderCapture
	protocol := "1.1"
	writeInformational := func(code int, header textproto.MIMEHeader, fromUpstream bool) bool {
		mu.Lock()
		defer mu.Unlock()
		if done {
			return false
		}
		var head http1ResponseHead
		if fromUpstream && capture != nil {
			head = capture.next()
			if head.status != code {
				return false
			}
		}
		if !req.ProtoAtLeast(1, 1) {
			return true
		}
		if code == http.StatusContinue {
			if sentContinue {
				return true
			}
			sentContinue = true
		}
		h := http.Header(header).Clone()
		removeConnectionHeaders(h, head.connection)
		removeHopByHopHeaders(h)
		if fromUpstream {
			if head.protocol == "" {
				head.protocol = protocol
			}
			if h == nil {
				h = make(http.Header)
			}
			h.Add("Via", head.protocol+" "+s.viaName)
		}
		copyHeader(w.Header(), h)
		w.WriteHeader(code)
		// net/http keeps the header map after informational responses.
		for key := range h {
			w.Header().Del(key)
		}
		return true
	}
	trace, stopUploadTimer := upstreamWriteTrace(s.cfg.UpstreamWriteTimeout, onWriteTimeout)
	defer stopUploadTimer()
	advertiseTrailers := req.Header.Get("Te") == "trailers"
	startUpload := trace.GotConn
	trace.GotConn = func(info httptrace.GotConnInfo) {
		mu.Lock()
		capture = nil
		protocol = "1.1"
		if conn, ok := info.Conn.(*http1Conn); ok {
			capture = conn.startHeaderCapture()
		}
		if conn, ok := info.Conn.(*tls.Conn); ok && conn.ConnectionState().NegotiatedProtocol == "h2" {
			protocol = "2"
		}
		if advertiseTrailers {
			// Transport calls GotConn before writing request headers. HTTP/1
			// requires the TE connection option, which HTTP/2 forbids.
			if protocol == "2" {
				req.Header.Del("Connection")
			} else {
				req.Header.Set("Connection", "TE")
			}
		}
		mu.Unlock()
		startUpload(info)
	}
	trace.Got1xxResponse = func(code int, header textproto.MIMEHeader) error {
		if code == http.StatusSwitchingProtocols {
			return errUpstreamUpgrade
		}
		if !writeInformational(code, header, true) {
			return errUpstreamResponseHead
		}
		return nil
	}
	if req.ProtoAtLeast(1, 1) && expectContinue && req.ContentLength != 0 && req.Body != nil {
		// Serialize 100 with the other informational writes. Sending it
		// explicitly disables net/http's automatic 100 on the first read.
		req.Body = &expectContinueBody{ReadCloser: req.Body, start: func() bool {
			return writeInformational(http.StatusContinue, nil, false)
		}}
	}
	resp, err := s.transport.RoundTrip(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
	mu.Lock()
	done = true
	if err == nil && capture != nil {
		head := capture.next()
		if head.status != resp.StatusCode {
			err = errUpstreamResponseHead
		} else if len(head.connection) > 0 {
			resp.Header["Connection"] = head.connection
		}
	}
	mu.Unlock()
	if err != nil && resp != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	return resp, err
}

func upstreamWriteTrace(timeout time.Duration, onTimeout func()) (*httptrace.ClientTrace, func()) {
	var mu sync.Mutex
	var timer *time.Timer
	stop := func() {
		mu.Lock()
		defer mu.Unlock()
		if timer != nil {
			timer.Stop()
			timer = nil
		}
	}
	trace := &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			mu.Lock()
			defer mu.Unlock()
			if timer != nil {
				timer.Stop()
			}
			var attempt *time.Timer
			attempt = time.AfterFunc(timeout, func() {
				mu.Lock()
				defer mu.Unlock()
				if timer == attempt {
					onTimeout()
				}
			})
			timer = attempt
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { stop() },
	}
	return trace, stop
}

type expectContinueBody struct {
	io.ReadCloser
	start func() bool
}

func (b *expectContinueBody) Read(p []byte) (int, error) {
	if b.start != nil {
		if !b.start() {
			return 0, io.ErrClosedPipe
		}
		b.start = nil
	}
	return b.ReadCloser.Read(p)
}

type flushingWriter struct {
	io.Writer
	flush func() error
}

type clientResponseWriter struct {
	http.ResponseWriter
	controller *http.ResponseController
	timeout    time.Duration
}

func (w *clientResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *clientResponseWriter) armWriteDeadline() error {
	err := w.controller.SetWriteDeadline(time.Now().Add(w.timeout))
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

func (w *clientResponseWriter) clearWriteDeadline() {
	_ = w.controller.SetWriteDeadline(time.Time{})
}

func (w *clientResponseWriter) WriteHeader(code int) {
	_ = w.armWriteDeadline()
	defer w.clearWriteDeadline()
	w.ResponseWriter.WriteHeader(code)
}

func (w *clientResponseWriter) Write(p []byte) (int, error) {
	if err := w.armWriteDeadline(); err != nil {
		return 0, err
	}
	defer w.clearWriteDeadline()
	return w.ResponseWriter.Write(p)
}

func (w *clientResponseWriter) flush() error {
	if err := w.armWriteDeadline(); err != nil {
		return err
	}
	defer w.clearWriteDeadline()
	err := w.controller.Flush()
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

func (w flushingWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err == nil {
		err = w.flush()
	}
	return n, err
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		localHTTPError(w, r, "CONNECT cannot contain a request body", http.StatusBadRequest)
		return
	}
	if r.URL == nil || r.URL.Scheme != "" || r.URL.Opaque != "" || r.URL.Path != "" ||
		r.URL.User != nil || r.URL.ForceQuery || r.URL.RawQuery != "" || r.URL.Fragment != "" {
		localHTTPError(w, r, "bad CONNECT target", http.StatusBadRequest)
		return
	}
	target, err := normalizeConnectTarget(r.URL.Host)
	if err != nil {
		localHTTPError(w, r, "bad CONNECT target", http.StatusBadRequest)
		return
	}

	dialCtx, cancel := context.WithTimeout(r.Context(), s.cfg.DialTimeout)
	upstream, err := s.dialer.DialContext(dialCtx, "tcp", target)
	dialContextErr := dialCtx.Err()
	cancel()
	if err != nil {
		status := upstreamErrorStatus(err)
		if errors.Is(err, errUpstreamAddressDenied) {
			status = http.StatusForbidden
		}
		if errors.Is(dialContextErr, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		message := "upstream connection failed"
		switch status {
		case http.StatusForbidden:
			message = "upstream address is not allowed"
		case http.StatusGatewayTimeout:
			message = "upstream connection timed out"
		}
		http.Error(w, message, status)
		s.logf("CONNECT %q failed: %q", target, err.Error())
		return
	}
	trackedUpstream := s.trackConn(upstream, false)
	if trackedUpstream == nil {
		return
	}
	defer trackedUpstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT is not supported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hijacker.Hijack()
	if err != nil {
		s.logf("CONNECT %q hijack failed: %q", target, err.Error())
		return
	}
	defer client.Close()
	_ = client.SetDeadline(time.Time{})

	if _, err := io.WriteString(buf, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buf.Flush(); err != nil {
		return
	}

	if s.cfg.Verbose {
		s.logf("CONNECT %q established", target)
	}
	relay(client, buf.Reader, trackedUpstream, s.cfg.TunnelHalfCloseTimeout, s.cfg.TunnelWriteTimeout)
}

func validHTTPAuthority(authority string) bool {
	if authority == "" || strings.ContainsAny(authority, "/\\@?# \t\r\n") {
		return false
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
			host, port = authority[1:len(authority)-1], ""
		} else if strings.ContainsAny(authority, ":[]") {
			return false
		} else {
			host, port = authority, ""
		}
	}
	if host == "" {
		return false
	}
	if strings.HasPrefix(authority, "[") {
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() {
			return false
		}
	} else if strings.Contains(host, "%") {
		return false
	}
	if port == "" {
		return true // HTTP uses the scheme's default for an empty port.
	}
	_, err = parseTCPPort(port)
	return err == nil
}

func normalizeConnectTarget(authority string) (string, error) {
	if strings.ContainsAny(authority, "/\\@?# \t\r\n") {
		return "", errors.New("invalid target")
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil || host == "" {
		return "", errors.New("CONNECT requires a host and port")
	}
	if strings.HasPrefix(authority, "[") {
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() {
			return "", errors.New("invalid bracketed host")
		}
	}
	portNum, err := parseTCPPort(port)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.FormatUint(portNum, 10)), nil
}

func parseTCPPort(port string) (uint64, error) {
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return 0, errors.New("invalid port")
	}
	return number, nil
}

func removeHopByHopHeaders(header http.Header) {
	removeConnectionHeaders(header, header.Values("Connection"))
	for _, name := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authentication-Info",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
}

func removeConnectionHeaders(header http.Header, connection []string) {
	for _, value := range connection {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				header.Del(name)
			}
		}
	}
}

func copyHeader(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}
