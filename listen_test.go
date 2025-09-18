package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func Test_netcat_runListen_tcp(t *testing.T) {
	nc := &netcat{
		stdin:  bytes.NewBufferString("test stdin data"),
		stdout: &bytes.Buffer{},
		cfg: &Config{
			NetcatMode: NetcatModeListen,
			Socket:     SocketTCP,
			Host:       "127.0.0.1",
			Port:       5000,
		},
		log: NewLogger(log.New(io.Discard, "", 0), &Config{}),
	}
	addr, err := nc.cfg.Address()
	if err != nil {
		t.Fatalf("failed to get address: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- nc.runListen(nc.cfg.Network(), addr)
	}()

	time.Sleep(100 * time.Millisecond) // Give the listener a moment to start

	// Check if runListen failed to start server
	select {
	case err := <-done:
		t.Fatalf("runListen failed %v", err)
	default:
	}

	conn, err := net.Dial(nc.cfg.Network(), addr)
	if err != nil {
		t.Fatalf("failed to connect to listener: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Errorf("failed to read from connection: %v", err)
	}
	if string(buf[:n]) != "test stdin data" {
		t.Errorf("expected buffer to be %q, got %q", "test stdin data", string(buf[:n]))
	}
	if _, err = conn.Write([]byte("test conn data")); err != nil {
		t.Errorf("failed to write to connection: %v", err)
	}
	if err := conn.(WriteCloser).CloseWrite(); err != nil {
		t.Errorf("failed to close write: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not exit in time")
	}

	if got := nc.stdout.(*bytes.Buffer).String(); got != "test conn data" {
		t.Errorf("expected stdout to be %q, got %q", "test conn data", got)
	}
}

func Test_netcat_runListen_unix(t *testing.T) {
	socket := os.TempDir() + "/gonc_test.sock"
	t.Cleanup(func() {
		time.Sleep(1000 * time.Millisecond)
		_ = os.Remove(socket) // Clean up after test
	})

	nc := &netcat{
		stdin:  bytes.NewBufferString("test stdin data"),
		stdout: &bytes.Buffer{},
		cfg: &Config{
			NetcatMode: NetcatModeListen,
			Socket:     SocketUnix,
			Host:       socket,
		},
		log: NewLogger(log.New(io.Discard, "", 0), &Config{}),
	}
	addr, err := nc.cfg.Address()
	if err != nil {
		t.Fatalf("failed to get address: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- nc.runListen(nc.cfg.Network(), addr)
	}()

	time.Sleep(100 * time.Millisecond) // Give the listener a moment to start

	// Check if runListen failed to start server
	select {
	case err := <-done:
		t.Fatalf("runListen failed %v", err)
	default:
	}

	conn, err := net.Dial(nc.cfg.Network(), addr)
	if err != nil {
		t.Fatalf("failed to connect to listener: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Errorf("failed to read from connection: %v", err)
	}
	if string(buf[:n]) != "test stdin data" {
		t.Errorf("expected buffer to be %q, got %q", "test stdin data", string(buf[:n]))
	}
	if _, err = conn.Write([]byte("test conn data")); err != nil {
		t.Errorf("failed to write to connection: %v", err)
	}
	if err := conn.(WriteCloser).CloseWrite(); err != nil {
		t.Errorf("failed to close write: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not exit in time")
	}

	if got := nc.stdout.(*bytes.Buffer).String(); got != "test conn data" {
		t.Errorf("expected stdout to be %q, got %q", "test conn data", got)
	}
}

func Test_netcat_runListen_udp(t *testing.T) {
	nc := &netcat{
		stdin:  bytes.NewBufferString("test stdin data"),
		stdout: &bytes.Buffer{},
		cfg: &Config{
			NetcatMode: NetcatModeListen,
			Socket:     SocketUDP,
			Host:       "127.0.0.1",
			Port:       5000,
		},
		log: NewLogger(log.New(io.Discard, "", 0), &Config{}),
	}
	addr, err := nc.cfg.Address()
	if err != nil {
		t.Fatalf("failed to get address: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- nc.runListen(nc.cfg.Network(), addr)
	}()

	time.Sleep(100 * time.Millisecond) // Give the listener a moment to start

	// Check if runListen failed to start server
	select {
	case err := <-done:
		t.Fatalf("runListen failed %v", err)
	default:
	}

	conn, err := net.Dial(nc.cfg.Network(), addr)
	if err != nil {
		t.Fatalf("failed to connect to listener: %v", err)
	}
	if _, err := conn.Write([]byte("test conn data")); err != nil {
		t.Errorf("failed to write to connection: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Errorf("failed to read from connection: %v", err)
	}
	if string(buf[:n]) != "test stdin data" {
		t.Errorf("expected buffer to be %q, got %q", "test stdin data", string(buf[:]))
	}
	time.Sleep(100 * time.Millisecond)
	// Send empty packet to signal EOF
	if _, err := conn.Write([]byte{}); err != nil {
		t.Errorf("failed to write to connection: %v", err)
	}
	conn.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not exit in time")
	}

	if got := nc.stdout.(*bytes.Buffer).String(); got != "test conn data" {
		t.Errorf("expected stdout to be %q, got %q", "test conn data", got)
	}
}

func Test_netcat_runListen_unixgram(t *testing.T) {
	socket := os.TempDir() + "/gonc_test.sock"
	t.Cleanup(func() {
		_ = os.Remove(socket) // Clean up after test
	})

	nc := &netcat{
		stdin:  bytes.NewBufferString("test stdin data"),
		stdout: &bytes.Buffer{},
		cfg: &Config{
			NetcatMode: NetcatModeListen,
			Socket:     SocketUnixgram,
			Host:       socket,
		},
		log: NewLogger(log.New(io.Discard, "", 0), &Config{Verbose: true}),
	}
	addr, err := nc.cfg.Address()
	if err != nil {
		t.Fatalf("failed to get address: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- nc.runListen(nc.cfg.Network(), addr)
	}()

	time.Sleep(100 * time.Millisecond) // Give the listener a moment to start

	// Check if runListen failed to start server
	select {
	case err := <-done:
		t.Fatalf("runListen failed %v", err)
	default:
	}

	clientSocket := filepath.Join(os.TempDir(), fmt.Sprintf("gonc-%x.sock", rand.Uint64()))
	t.Cleanup(func() {
		_ = os.Remove(clientSocket)
	})

	var dialer net.Dialer
	dialer.LocalAddr, err = net.ResolveUnixAddr(nc.cfg.Network(), clientSocket)
	if err != nil {
		t.Fatalf("failed to resolve local address: %v", err)
	}
	conn, err := dialer.Dial(nc.cfg.Network(), addr)
	if err != nil {
		t.Fatalf("failed to connect to listener: %v", err)
	}
	if _, err := conn.Write([]byte("test conn data")); err != nil {
		t.Errorf("failed to write to connection: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Errorf("failed to read from connection: %v", err)
	}
	if string(buf[:n]) != "test stdin data" {
		t.Errorf("expected buffer to be %q, got %q", "test stdin data", string(buf[:]))
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := conn.Write([]byte{}); err != nil {
		t.Errorf("failed to write to connection: %v", err)
	}
	conn.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not exit in time")
	}

	if got := nc.stdout.(*bytes.Buffer).String(); got != "test conn data" {
		t.Errorf("expected stdout to be %q, got %q", "test conn data", got)
	}
}

func Test_netcat_runListen_ssl(t *testing.T) {
	tcases := []struct {
		name    string
		ciphers []uint16
		alpn    []string
	}{
		{
			name: "basic ssl connection",
		},
		{
			name:    "ssl connection specific cipher",
			ciphers: []uint16{tls.TLS_AES_128_GCM_SHA256},
		},
		{
			name: "ssl connection specific alpn",
			alpn: []string{"h2"},
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			nc := &netcat{
				stdin:  bytes.NewBufferString("test stdin data"),
				stdout: &bytes.Buffer{},
				cfg: &Config{
					NetcatMode: NetcatModeListen,
					Socket:     SocketTCP,
					Host:       "localhost",
					Port:       8443,
					UseSSL:     true,
					SSLCert:    "testdata/test_cert.pem",
					SSLKey:     "testdata/test_key.pem",
					SSLCiphers: tc.ciphers,
					SSLAlpn:    tc.alpn,
				},
				log: NewLogger(log.New(io.Discard, "", 0), &Config{}),
			}

			addr, err := nc.cfg.Address()
			if err != nil {
				t.Fatalf("failed to get address: %v", err)
			}

			done := make(chan error, 1)
			go func() {
				done <- nc.runListen(nc.cfg.Network(), addr)
			}()

			time.Sleep(100 * time.Millisecond) // Give the listener a moment to start

			// Check if runListen failed to start server
			select {
			case err := <-done:
				t.Fatalf("runListen failed %v", err)
			default:
			}
			conn, err := tls.Dial(nc.cfg.Network(), addr, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         tc.alpn,
			})
			if err != nil {
				t.Fatalf("failed to connect to listener: %v", err)
			}

			if err := conn.Handshake(); err != nil {
				t.Fatalf("failed to complete handshake: %v", err)
			}
			if len(tc.ciphers) > 0 && !slices.Contains(tc.ciphers, conn.ConnectionState().CipherSuite) {
				t.Errorf("negotiated cipher suite %d is not in requested list %v", conn.ConnectionState().CipherSuite, tc.ciphers)
			}
			if tc.alpn != nil && !slices.Contains(tc.alpn, conn.ConnectionState().NegotiatedProtocol) {
				t.Errorf("expected ALPN to be one of %q, got %q", tc.alpn, conn.ConnectionState().NegotiatedProtocol)
			}

			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil && err != io.EOF {
				t.Errorf("failed to read from connection: %v", err)
			}
			if string(buf[:n]) != "test stdin data" {
				t.Errorf("expected buffer to be %q, got %q", "test stdin data", string(buf[:n]))
			}
			if _, err = conn.Write([]byte("test conn data")); err != nil {
				t.Errorf("failed to write to connection: %v", err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Errorf("failed to close write: %v", err)
			}

			select {
			case err := <-done:
				if err != nil {
					t.Errorf("expected nil error, got %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("listener did not exit in time")
			}

			if got := nc.stdout.(*bytes.Buffer).String(); got != "test conn data" {
				t.Errorf("expected stdout to be %q, got %q", "test conn data", got)
			}
		})
	}
}

func Test_netcat_runListen_createListenerError(t *testing.T) {
	nc := &netcat{
		cfg: &Config{
			Socket: SocketTCP,
		},
	}

	err := nc.runListen("tcp", "invalid:address")
	if err == nil || !strings.Contains(err.Error(), "createListener") {
		t.Errorf("expected createListener error, got: %v", err)
	}
}

func Test_netcat_accept_error(t *testing.T) {
	nc := &netcat{
		stdin:  &bytes.Buffer{},
		stdout: &bytes.Buffer{},
		cfg: &Config{
			Socket: SocketTCP,
		},
	}

	// mockListener that returns error on Accept
	mockListener := &mockListener{
		addr:      &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
		acceptErr: fmt.Errorf("mock accept error"),
	}
	err := nc.accept(mockListener)
	if err == nil || !strings.Contains(err.Error(), "acceptConn") {
		t.Errorf("expected acceptConn error, got: %v", err)
	}
}

func Test_netcat_acceptForever_stops_on_error(t *testing.T) {
	nc := &netcat{
		stdin:  &bytes.Buffer{},
		stdout: &bytes.Buffer{},
		cfg: &Config{
			Socket: SocketTCP,
		},
	}

	mockListener := &mockListener{
		addr:      &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
		acceptErr: fmt.Errorf("mock error"),
	}
	err := nc.acceptForever(mockListener)
	if err == nil || !strings.Contains(err.Error(), "accept") {
		t.Errorf("expected accept error, got: %v", err)
	}
}

func Test_netcat_createListener_tcp(t *testing.T) {
	nc := &netcat{
		cfg: &Config{
			Socket: SocketTCP,
		},
	}
	ln, err := nc.createListener("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	if ln == nil {
		t.Errorf("expected listener, got nil")
	}
	if ln.Addr().Network() != "tcp" {
		t.Errorf("expected tcp listener, got %q", ln.Addr().Network())
	}
	if !strings.HasPrefix(ln.Addr().String(), "127.0.0.1:") {
		t.Errorf("expected non-empty listener address, got %q", ln.Addr().String())
	}
}

func Test_netcat_createListener_unix(t *testing.T) {
	nc := &netcat{
		cfg: &Config{
			Socket: SocketUnix,
		},
	}
	socket := os.TempDir() + "/gonc_test.sock"
	defer os.Remove(socket)

	ln, err := nc.createListener("unix", socket)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	if ln == nil {
		t.Errorf("expected listener, got nil")
	}
	if ln.Addr().Network() != "unix" {
		t.Errorf("expected unix listener, got %q", ln.Addr().Network())
	}
	if ln.Addr().String() != socket {
		t.Errorf("expected listener address to be %q, got %q", socket, ln.Addr().String())
	}
}

func Test_netcat_createListener_udp(t *testing.T) {
	nc := &netcat{
		cfg: &Config{
			Socket: SocketUDP,
		},
	}
	ln, err := nc.createListener("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	if ln == nil {
		t.Errorf("expected listener, got nil")
	}
	if ln.Addr().Network() != "udp" {
		t.Errorf("expected udp listener, got %q", ln.Addr().Network())
	}
	if !strings.HasPrefix(ln.Addr().String(), "127.0.0.1:") {
		t.Errorf("expected non-empty listener address, got %q", ln.Addr().String())
	}
	if _, ok := ln.(*UDPListener); !ok {
		t.Errorf("expected UDPListener, got %T", ln)
	}
}

func Test_netcat_createListener_unixgram(t *testing.T) {
	nc := &netcat{
		cfg: &Config{
			Socket: SocketUnixgram,
		},
	}
	socket := os.TempDir() + "/gonc_test.sock"
	defer os.Remove(socket)

	ln, err := nc.createListener("unixgram", socket)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	if ln == nil {
		t.Errorf("expected listener, got nil")
	}
	if ln.Addr().Network() != "unixgram" {
		t.Errorf("expected unixgram listener, got %q", ln.Addr().Network())
	}
	if ln.Addr().String() != socket {
		t.Errorf("expected listener address to be %q, got %q", socket, ln.Addr().String())
	}
	if _, ok := ln.(*UDPListener); !ok {
		t.Errorf("expected UDPListener, got %T", ln)
	}
}

func Test_netcat_createListener_tls(t *testing.T) {
	nc := &netcat{
		stdin:  &bytes.Buffer{},
		stdout: &bytes.Buffer{},
		cfg: &Config{
			Socket:     SocketTCP,
			UseSSL:     true,
			SSLCert:    "testdata/test_cert.pem",
			SSLKey:     "testdata/test_key.pem",
			SSLCiphers: nil,
		},
		log: NewLogger(log.New(&bytes.Buffer{}, "", 0), &Config{Verbose: true}),
	}

	ln, err := nc.createListener("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	defer ln.Close()

	if ln == nil {
		t.Errorf("expected listener, got nil")
	}
	if ln.Addr().Network() != "tcp" {
		t.Errorf("expected tcp listener, got %q", ln.Addr().Network())
	}
	if !strings.HasPrefix(ln.Addr().String(), "127.0.0.1:") {
		t.Errorf("expected non-empty listener address, got %q", ln.Addr().String())
	}

	// Try accepting a connection to ensure TLS handshake works
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("failed to accept TLS connection: %v", err)
			return
		}
		defer conn.Close()

		_, _ = conn.Write([]byte("hello"))
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("failed to connect to TLS listener: %v", err)
	}
	defer conn.Close()

	data, _ := io.ReadAll(conn)
	if !bytes.Equal(data, []byte("hello")) {
		t.Errorf("expected \"hello\", got %q", data)
	}
}

func Test_netcat_createListener_tls_missing_cert(t *testing.T) {
	nc := &netcat{
		cfg: &Config{
			Socket:  SocketTCP,
			UseSSL:  true,
			SSLCert: "does-not-exist",
			SSLKey:  "does-not-exist",
		},
	}
	_, err := nc.createListener("tcp", "127.0.0.1:0")
	if err == nil || !strings.Contains(err.Error(), "LoadX509KeyPair") {
		t.Errorf("expected missing SSL certificate error, got: %v", err)
	}
}

func Test_netcat_createListener_unsupported_socket(t *testing.T) {
	nc := &netcat{
		cfg: &Config{
			Socket: Socket("unsupported"),
		},
	}
	ln, err := nc.createListener("tcp", "127.0.0.1:0")
	if err == nil || !strings.Contains(err.Error(), "unsupported socket type") {
		t.Errorf("expected unsupported socket type error, got: %v", err)
	}
	if ln != nil {
		t.Errorf("expected nil listener for unsupported socket type")
	}
}

func Test_netcat_acceptConn(t *testing.T) {
	tcases := []struct {
		name    string
		timeout time.Duration
	}{
		{
			name: "accept connection",
		},
		{
			name:    "accept connection with timeout",
			timeout: 5 * time.Second,
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			logBuf := &bytes.Buffer{}
			nc := &netcat{
				cfg: &Config{
					Socket:  SocketTCP,
					Timeout: tc.timeout,
				},
				log: NewLogger(log.New(logBuf, "", 0), &Config{}),
			}

			ln := &mockListener{
				addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
			}
			conn, err := nc.acceptConn(ln)
			if err != nil {
				t.Fatalf("failed to accept connection: %v", err)
			}
			defer conn.Close()

			if conn == nil {
				t.Errorf("expected connection, got nil")
			}

			select {
			case <-conn.(*mockNetConn).setDeadlineCh:
				if tc.timeout == 0 {
					t.Errorf("expected SetDeadline not to be called")
				}
			default:
				if tc.timeout > 0 {
					t.Error("expected SetDeadline to be called")
				}
			}

			if strings.Contains(logBuf.String(), fmt.Sprintf("Connection received on %s", ln.addr.String())) {
				t.Errorf("expected log message, got none")
			}
		})
	}
}
