package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

const (
	socks5Version = 0x05

	socksMethodNoAuth       = 0x00
	socksMethodUserPassword = 0x02
	socksMethodNoAcceptable = 0xff

	socksCmdConnect = 0x01

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksRepSucceeded           = 0x00
	socksRepGeneralFailure      = 0x01
	socksRepNotAllowed          = 0x02
	socksRepNetworkUnreachable  = 0x03
	socksRepHostUnreachable     = 0x04
	socksRepConnectionRefused   = 0x05
	socksRepTTLExpired          = 0x06
	socksRepCommandNotSupported = 0x07
	socksRepAddressNotSupported = 0x08
)

var errSOCKSEarlyDataLimit = errors.New("too much data before SOCKS5 CONNECT reply")

func (s *Server) handleSOCKS5(ctx context.Context, conn net.Conn, reader *bufio.Reader) {
	defer conn.Close()
	handshakeDeadline := time.Now().Add(handshakeTimeout)
	_ = conn.SetDeadline(handshakeDeadline)

	methods, err := readSOCKSMethods(reader)
	if err != nil {
		s.debug("SOCKS5 greeting failed from %s: %v", conn.RemoteAddr(), err)
		return
	}

	method := byte(socksMethodNoAcceptable)
	if s.auth.enabled {
		if containsByte(methods, socksMethodUserPassword) {
			method = socksMethodUserPassword
		}
	} else if containsByte(methods, socksMethodNoAuth) {
		method = socksMethodNoAuth
	}
	if err := writeAll(conn, []byte{socks5Version, method}); err != nil {
		return
	}
	if method == socksMethodNoAcceptable {
		s.debug("SOCKS5 client %s offered no supported authentication method", conn.RemoteAddr())
		return
	}
	if method == socksMethodUserPassword {
		if err := s.authenticateSOCKS5(conn, reader); err != nil {
			s.debug("SOCKS5 authentication failed from %s: %v", conn.RemoteAddr(), err)
			return
		}
	}

	target, err := readSOCKSConnectRequest(reader)
	if err != nil {
		var requestErr *socksRequestError
		if errors.As(err, &requestErr) {
			_ = writeSOCKSReply(conn, requestErr.reply, nil)
		}
		s.debug("SOCKS5 request failed from %s: %v", conn.RemoteAddr(), err)
		return
	}

	upstream, err := s.dialSOCKSTarget(ctx, conn, reader, target, handshakeDeadline)
	if err != nil {
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return
		}
		reply := socksReplyForDialError(err)
		_ = writeSOCKSReply(conn, reply, nil)
		s.logf("SOCKS5 CONNECT %q failed: %q", target, err.Error())
		return
	}
	trackedUpstream := s.trackConn(upstream, false)
	if trackedUpstream == nil {
		return
	}
	defer trackedUpstream.Close()

	if err := writeSOCKSReply(conn, socksRepSucceeded, upstream.LocalAddr().(*net.TCPAddr)); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	if s.cfg.Verbose {
		s.logf("SOCKS5 CONNECT %q established", target)
	}
	relay(conn, reader, trackedUpstream, s.cfg.TunnelHalfCloseTimeout, s.cfg.TunnelWriteTimeout)
}

func (s *Server) dialSOCKSTarget(ctx context.Context, conn net.Conn, reader *bufio.Reader, target string, handshakeDeadline time.Time) (net.Conn, error) {
	deadline := time.Now().Add(s.cfg.DialTimeout)
	if handshakeDeadline.Before(deadline) {
		deadline = handshakeDeadline
	}
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	monitorDone := make(chan struct{})
	var monitorErr error
	go func() {
		defer close(monitorDone)
		monitorErr = monitorSOCKSClient(conn, reader)
		if monitorErr != nil && !errors.Is(monitorErr, os.ErrDeadlineExceeded) {
			cancel()
		}
	}()

	upstream, err := s.dialer.DialContext(dialCtx, "tcp", target)
	// Interrupt the read and wait until it releases the reader before
	// relaying. The caller clears deadlines when it starts the tunnel.
	_ = conn.SetReadDeadline(time.Now())
	<-monitorDone
	if errors.Is(monitorErr, errSOCKSEarlyDataLimit) {
		err = monitorErr
	} else if contextErr := dialCtx.Err(); contextErr != nil {
		err = contextErr
	}
	if err != nil && upstream != nil {
		_ = upstream.Close()
		upstream = nil
	}
	return upstream, err
}

func monitorSOCKSClient(conn net.Conn, reader *bufio.Reader) error {
	// Peek past buffered data so it is still available when relaying.
	for reader.Buffered() < reader.Size() {
		if _, err := reader.Peek(reader.Buffered() + 1); err != nil {
			return err
		}
	}
	// Keep watching for EOF with a full buffer. One more byte means
	// the client exceeded the amount of data we can retain before dialing.
	var extra [1]byte
	n, err := conn.Read(extra[:])
	if n > 0 {
		return errSOCKSEarlyDataLimit
	}
	return err
}

func readSOCKSMethods(reader *bufio.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != socks5Version {
		return nil, fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	count := int(header[1])
	if count == 0 {
		return nil, errors.New("no authentication methods offered")
	}
	methods := make([]byte, count)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return nil, err
	}
	return methods, nil
}

func (s *Server) authenticateSOCKS5(conn net.Conn, reader *bufio.Reader) error {
	version, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if version != 0x01 {
		return fmt.Errorf("unsupported authentication version %d", version)
	}

	username, err := readSOCKSString(reader)
	if err != nil {
		return err
	}
	password, err := readSOCKSString(reader)
	if err != nil {
		return err
	}

	ok := s.auth.checkSOCKS5(username, password)
	status := byte(0x01)
	if ok {
		status = 0x00
	}
	if err := writeAll(conn, []byte{0x01, status}); err != nil {
		return err
	}
	if !ok {
		return errors.New("invalid username or password")
	}
	return nil
}

func readSOCKSString(reader *bufio.Reader) ([]byte, error) {
	length, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, errors.New("empty credential field")
	}
	value := make([]byte, int(length))
	if _, err := io.ReadFull(reader, value); err != nil {
		return nil, err
	}
	return value, nil
}

type socksRequestError struct {
	reply byte
	err   error
}

func (e *socksRequestError) Error() string {
	return e.err.Error()
}

func (e *socksRequestError) Unwrap() error {
	return e.err
}

func readSOCKSConnectRequest(reader *bufio.Reader) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", err
	}
	if header[0] != socks5Version {
		return "", fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	if header[1] != socksCmdConnect {
		return "", &socksRequestError{
			reply: socksRepCommandNotSupported,
			err:   fmt.Errorf("unsupported SOCKS command %d", header[1]),
		}
	}
	if header[2] != 0 {
		return "", errors.New("invalid reserved byte")
	}

	var host string
	switch header[3] {
	case socksAtypIPv4:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case socksAtypIPv6:
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case socksAtypDomain:
		length, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if length == 0 {
			return "", &socksRequestError{
				reply: socksRepAddressNotSupported,
				err:   errors.New("empty domain name"),
			}
		}
		address := make([]byte, int(length))
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		host = string(address)
	default:
		return "", &socksRequestError{
			reply: socksRepAddressNotSupported,
			err:   fmt.Errorf("unsupported address type %d", header[3]),
		}
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)
	if port == 0 {
		return "", &socksRequestError{
			reply: socksRepGeneralFailure,
			err:   errors.New("invalid target port 0"),
		}
	}

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func writeSOCKSReply(w io.Writer, reply byte, bound *net.TCPAddr) error {
	if bound == nil {
		return writeAll(w, []byte{socks5Version, reply, 0, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	}

	response := []byte{socks5Version, reply, 0}
	if ip := bound.IP.To4(); ip != nil {
		response = append(response, socksAtypIPv4)
		response = append(response, ip...)
	} else {
		response = append(response, socksAtypIPv6)
		response = append(response, bound.IP.To16()...)
	}
	return writeAll(w, binary.BigEndian.AppendUint16(response, uint16(bound.Port)))
}

func socksReplyForDialError(err error) byte {
	const (
		wsaNetworkUnreachable = 10051
		wsaConnectionRefused  = 10061
		wsaHostUnreachable    = 10065
	)
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, errUpstreamAddressDenied):
		return socksRepNotAllowed
	case errors.Is(err, context.DeadlineExceeded), os.IsTimeout(err):
		return socksRepTTLExpired
	case matchesSocketError(err, syscall.ECONNREFUSED, wsaConnectionRefused):
		return socksRepConnectionRefused
	case matchesSocketError(err, syscall.ENETUNREACH, wsaNetworkUnreachable):
		return socksRepNetworkUnreachable
	case matchesSocketError(err, syscall.EHOSTUNREACH, wsaHostUnreachable):
		return socksRepHostUnreachable
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return socksRepHostUnreachable
	default:
		return socksRepGeneralFailure
	}
}

func matchesSocketError(err error, standard, winsock syscall.Errno) bool {
	return errors.Is(err, standard) || (runtime.GOOS == "windows" && errors.Is(err, winsock))
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func containsByte(values []byte, target byte) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (s *Server) debug(format string, args ...any) {
	if s.cfg.Verbose {
		s.logf(format, args...)
	}
}
