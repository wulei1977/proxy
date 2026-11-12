package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sniffTimeout     = 10 * time.Second
	handshakeTimeout = 30 * time.Second
)

// DefaultMaxConnections is the shared limit on concurrent client connections.
const DefaultMaxConnections = 256

// DefaultRequestReadTimeout is the default time limit for reading an HTTP request.
const DefaultRequestReadTimeout = 15 * time.Second

// DefaultResponseHeaderTimeout limits the wait for upstream response headers.
const DefaultResponseHeaderTimeout = 15 * time.Second

// DefaultUpstreamWriteTimeout bounds the time to send a request upstream.
const DefaultUpstreamWriteTimeout = 15 * time.Second

// DefaultClientWriteTimeout bounds an individual HTTP response write.
const DefaultClientWriteTimeout = 15 * time.Second

// DefaultResponseBodyIdleTimeout limits the wait for the next upstream body bytes.
const DefaultResponseBodyIdleTimeout = 60 * time.Second

// DefaultTunnelHalfCloseTimeout limits inactivity after one tunnel direction ends.
const DefaultTunnelHalfCloseTimeout = 60 * time.Second

// DefaultTunnelWriteTimeout bounds a blocked tunnel write.
const DefaultTunnelWriteTimeout = 15 * time.Second

// Config controls the proxy server.
type Config struct {
	// ListenAddr is used by ListenAndServe. It defaults to 127.0.0.1:8080.
	ListenAddr string

	// MaxConnections limits accepted client sockets across all protocols.
	// Zero uses DefaultMaxConnections.
	MaxConnections int

	// Username and Password must both be set to enable authentication.
	// HTTP/HTTPS clients use Basic proxy authentication and SOCKS5 clients
	// use username/password authentication. Each field is at most 255 bytes.
	// Non-UTF-8 credentials can only authenticate SOCKS5 clients.
	Username string
	Password string

	// CertFile and KeyFile enable a custom certificate for the HTTPS proxy.
	// If both are empty, an ephemeral self-signed certificate is generated.
	CertFile string
	KeyFile  string

	// DialTimeout limits how long an outbound TCP connection may take.
	DialTimeout time.Duration

	// RequestReadTimeout limits the total time to read an HTTP request,
	// including its body. Nonpositive values use DefaultRequestReadTimeout.
	RequestReadTimeout time.Duration

	// ResponseHeaderTimeout starts after the request has been written upstream.
	// Nonpositive values use DefaultResponseHeaderTimeout.
	ResponseHeaderTimeout time.Duration

	// UpstreamWriteTimeout starts when an HTTP transport connection is ready.
	// Nonpositive values use DefaultUpstreamWriteTimeout.
	UpstreamWriteTimeout time.Duration

	// ClientWriteTimeout limits individual response writes and flushes.
	ClientWriteTimeout time.Duration

	// ResponseBodyIdleTimeout limits an upstream response body read.
	ResponseBodyIdleTimeout time.Duration

	// TunnelHalfCloseTimeout limits tunnel inactivity after one direction ends.
	TunnelHalfCloseTimeout time.Duration

	// TunnelWriteTimeout limits individual writes in either tunnel direction.
	TunnelWriteTimeout time.Duration

	// Verbose enables a log line for every proxied request.
	Verbose bool

	// Logger receives server logs. log.Default() is used when nil.
	Logger *log.Logger
}

// Server handles HTTP, HTTPS and SOCKS5 proxy traffic on one listener.
// The protocol is detected from the first byte sent by the client.
type Server struct {
	cfg             Config
	logger          *log.Logger
	auth            *authenticator
	tlsConfig       *tls.Config
	certFingerprint string
	certGenerated   bool
	dialer          *net.Dialer
	transport       *http.Transport
	viaName         string

	httpServer   *http.Server
	httpListener *connListener
	rawListener  net.Listener
	clientSlots  chan struct{}
	conns        sync.Map // *trackedConn -> struct{}
	shutdownOnce sync.Once
	serving      atomic.Bool
	closing      atomic.Bool
}

// New validates cfg and prepares the server. Call ListenAndServe or Serve
// afterwards to start accepting connections.
func New(cfg Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:8080"
	}
	if cfg.MaxConnections < 0 {
		return nil, errors.New("max connections must be positive")
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = DefaultMaxConnections
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.RequestReadTimeout <= 0 {
		cfg.RequestReadTimeout = DefaultRequestReadTimeout
	}
	if cfg.ResponseHeaderTimeout <= 0 {
		cfg.ResponseHeaderTimeout = DefaultResponseHeaderTimeout
	}
	if cfg.UpstreamWriteTimeout <= 0 {
		cfg.UpstreamWriteTimeout = DefaultUpstreamWriteTimeout
	}
	if cfg.ClientWriteTimeout <= 0 {
		cfg.ClientWriteTimeout = DefaultClientWriteTimeout
	}
	if cfg.ResponseBodyIdleTimeout <= 0 {
		cfg.ResponseBodyIdleTimeout = DefaultResponseBodyIdleTimeout
	}
	if cfg.TunnelHalfCloseTimeout <= 0 {
		cfg.TunnelHalfCloseTimeout = DefaultTunnelHalfCloseTimeout
	}
	if cfg.TunnelWriteTimeout <= 0 {
		cfg.TunnelWriteTimeout = DefaultTunnelWriteTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, errors.New("certificate and key files must be provided together")
	}
	if (cfg.Username == "") != (cfg.Password == "") {
		return nil, errors.New("proxy username and password must be provided together")
	}
	if len(cfg.Username) > 255 || len(cfg.Password) > 255 {
		return nil, errors.New("proxy username and password must each be at most 255 bytes")
	}
	if strings.Contains(cfg.Username, ":") {
		return nil, errors.New("proxy username cannot contain a colon")
	}
	isControl := func(r rune) bool { return r < 0x20 || r == 0x7f }
	if strings.ContainsFunc(cfg.Username, isControl) || strings.ContainsFunc(cfg.Password, isControl) {
		return nil, errors.New("proxy username and password cannot contain ASCII control characters")
	}

	tlsConfig, fingerprint, generated, err := loadTLSConfig(cfg.CertFile, cfg.KeyFile, cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	var viaID [16]byte
	if _, err := rand.Read(viaID[:]); err != nil {
		return nil, fmt.Errorf("generate Via pseudonym: %w", err)
	}

	dialer := &net.Dialer{
		Timeout:        cfg.DialTimeout,
		KeepAlive:      30 * time.Second,
		ControlContext: checkUpstreamAddress,
	}
	dialUpstream := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &upstreamConn{Conn: conn, writeTimeout: cfg.UpstreamWriteTimeout}, nil
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialUpstream(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &http1Conn{Conn: conn}, nil
		},
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    10,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		ResponseHeaderTimeout:  cfg.ResponseHeaderTimeout,
		MaxResponseHeaderBytes: maxUpstreamHeaderBytes,
	}
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialUpstream(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// The transport installs its HTTP/2 ALPN configuration before dialing.
		config := transport.TLSClientConfig.Clone()
		if config == nil {
			config = &tls.Config{}
		}
		if config.ServerName == "" {
			config.ServerName, _, _ = net.SplitHostPort(addr)
		}
		tlsConn := tls.Client(conn, config)
		handshakeCtx, cancel := context.WithTimeout(ctx, transport.TLSHandshakeTimeout)
		defer cancel()
		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
			return tlsConn, nil
		}
		return &http1Conn{Conn: tlsConn}, nil
	}

	return &Server{
		cfg:             cfg,
		logger:          cfg.Logger,
		auth:            newAuthenticator(cfg.Username, cfg.Password),
		tlsConfig:       tlsConfig,
		certFingerprint: fingerprint,
		certGenerated:   generated,
		dialer:          dialer,
		transport:       transport,
		viaName:         fmt.Sprintf("goproxy-%x", viaID),
		clientSlots:     make(chan struct{}, cfg.MaxConnections),
	}, nil
}

type upstreamConn struct {
	net.Conn
	writeTimeout time.Duration
	writeMu      sync.Mutex
	deadlineMu   sync.Mutex
	deadline     time.Time
	writeLimit   time.Time
}

func (c *upstreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.setWriteLimit(time.Now().Add(c.writeTimeout)); err != nil {
		return 0, err
	}
	defer c.setWriteLimit(time.Time{})
	return c.Conn.Write(p)
}

func (c *upstreamConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *upstreamConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.deadline = t
	return c.updateWriteDeadline()
}

func (c *upstreamConn) setWriteLimit(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeLimit = t
	return c.updateWriteDeadline()
}

func (c *upstreamConn) updateWriteDeadline() error {
	deadline := c.deadline
	if !c.writeLimit.IsZero() && (deadline.IsZero() || c.writeLimit.Before(deadline)) {
		deadline = c.writeLimit
	}
	return c.Conn.SetWriteDeadline(deadline)
}

// ListenAndServe listens on cfg.ListenAddr and serves until ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.ListenAddr, err)
	}
	defer ln.Close()
	return s.Serve(ctx, ln)
}

// Serve accepts connections from ln until ctx is canceled. It takes ownership
// of ln and closes it on shutdown.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if ln == nil {
		return errors.New("nil listener")
	}
	if !s.serving.CompareAndSwap(false, true) {
		return errors.New("server is already serving")
	}

	s.rawListener = ln
	s.httpListener = newConnListener(ln.Addr())
	s.httpServer = &http.Server{
		Handler:                      s,
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            min(15*time.Second, s.cfg.RequestReadTimeout),
		ReadTimeout:                  s.cfg.RequestReadTimeout,
		IdleTimeout:                  90 * time.Second,
		MaxHeaderBytes:               1 << 20,
		ErrorLog:                     s.logger,
	}

	s.logf("listening on %s (HTTP / HTTPS / SOCKS5)", ln.Addr())
	if s.auth.enabled {
		s.logf("authentication enabled for user %q", s.cfg.Username)
	}
	if s.certGenerated {
		s.logf("HTTPS proxy uses an ephemeral self-signed certificate")
	}
	s.logf("HTTPS proxy certificate SHA-256: %s", s.certFingerprint)

	errCh := make(chan error, 2)
	sessionCtx, cancelSessions := context.WithCancel(ctx)
	defer cancelSessions()
	go func() {
		errCh <- s.httpServer.Serve(s.httpListener)
	}()
	go func() {
		errCh <- s.acceptLoop(sessionCtx, ln)
	}()

	var serveErr error
	completed := 0
	select {
	case <-ctx.Done():
	case err := <-errCh:
		completed = 1
		if !isClosedError(err) {
			serveErr = err
		}
	}

	cancelSessions()
	s.shutdown()

	for completed < 2 {
		select {
		case err := <-errCh:
			completed++
			if serveErr == nil && !isClosedError(err) {
				serveErr = err
			}
		case <-time.After(3 * time.Second):
			if serveErr == nil {
				serveErr = errors.New("timed out waiting for server shutdown")
			}
			completed = 2
		}
	}

	s.transport.CloseIdleConnections()
	return serveErr
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener) error {
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			var temporary net.Error
			if errors.Is(err, net.ErrClosed) || !errors.As(err, &temporary) || !temporary.Temporary() {
				return err
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else {
				delay = min(2*delay, time.Second)
			}
			s.debug("accept failed temporarily: %v; retrying in %s", err, delay)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return net.ErrClosed
			case <-timer.C:
			}
			continue
		}
		delay = 0

		select {
		case s.clientSlots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		tracked := s.trackConn(conn, true)
		if tracked == nil {
			return net.ErrClosed
		}
		go s.dispatch(ctx, tracked)
	}
}

func (s *Server) trackConn(conn net.Conn, client bool) *trackedConn {
	tracked := &trackedConn{Conn: conn, server: s, client: client}
	s.conns.Store(tracked, struct{}{})
	if s.closing.Load() {
		_ = tracked.Close()
		return nil
	}
	return tracked
}

func (s *Server) dispatch(ctx context.Context, conn *trackedConn) {
	reader := bufio.NewReader(conn)

	_ = conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	first, err := reader.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return
	}

	switch first[0] {
	case socks5Version:
		s.handleSOCKS5(ctx, conn, reader)
	case 0x16: // TLS handshake record
		tlsConn := tls.Server(&bufferedConn{Conn: conn, reader: reader}, s.tlsConfig)
		if !s.httpListener.feed(tlsConn) {
			_ = tlsConn.Close()
		}
	default:
		if !s.httpListener.feed(&bufferedConn{Conn: conn, reader: reader}) {
			_ = conn.Close()
		}
	}
}

func (s *Server) shutdown() {
	s.shutdownOnce.Do(func() {
		s.closing.Store(true)
		if s.rawListener != nil {
			_ = s.rawListener.Close()
		}
		if s.httpServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.httpServer.Shutdown(ctx)
			cancel()
			_ = s.httpServer.Close()
		}
		if s.httpListener != nil {
			_ = s.httpListener.Close()
		}

		// Close both endpoints of active SOCKS5 and CONNECT tunnels.
		s.conns.Range(func(key, _ any) bool {
			if conn, ok := key.(*trackedConn); ok {
				_ = conn.Close()
			}
			return true
		})
	})
}

func (s *Server) logf(format string, args ...any) {
	s.logger.Printf(format, args...)
}

func isClosedError(err error) bool {
	return err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)
}

// trackedConn removes itself from the server's connection set when closed.
// It forwards half-close methods so CONNECT and SOCKS5 tunnels can propagate
// EOF in each direction.
type trackedConn struct {
	net.Conn
	server    *Server
	client    bool
	closeOnce sync.Once
}

func (c *trackedConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.server.conns.Delete(c)
		err = c.Conn.Close()
		if c.client {
			<-c.server.clientSlots
		}
	})
	return err
}

func (c *trackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *trackedConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// bufferedConn preserves bytes already read into a bufio.Reader when handing
// a connection to another protocol handler.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *bufferedConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// connListener turns hand-detected HTTP connections into a net.Listener for
// http.Server. Connections that turn out to be SOCKS5 never reach this
// listener.
type connListener struct {
	addr      net.Addr
	ch        chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func newConnListener(addr net.Addr) *connListener {
	return &connListener{
		addr: addr,
		ch:   make(chan net.Conn),
		done: make(chan struct{}),
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.ch:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
	})
	return nil
}

func (l *connListener) Addr() net.Addr {
	return l.addr
}

func (l *connListener) feed(conn net.Conn) bool {
	select {
	case l.ch <- conn:
		return true
	case <-l.done:
		return false
	}
}
