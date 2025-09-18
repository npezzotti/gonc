package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func Test_runConnect_tcp(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Errorf("failed to start test server: %v", err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() {
		var listenerErr error
		defer func() {
			done <- listenerErr
		}()

		conn, err := listener.Accept()
		if err != nil {
			listenerErr = err
			return
		}
		defer conn.Close()

		if _, err := conn.Write([]byte("test conn data")); err != nil {
			listenerErr = err
			return
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			listenerErr = err
			return
		}
		if string(buf[:n]) != "test stdin data" {
			listenerErr = fmt.Errorf("expected 'test stdin data', got %q", string(buf[:n]))
		}
	}()

	n := &netcat{
		stdin:  bytes.NewBufferString("test stdin data"),
		stdout: &bytes.Buffer{},
		cfg: &Config{
			NetcatMode: NetcatModeConnect,
			Socket:     SocketTCP,
		},
		log: NewLogger(log.New(io.Discard, "", 0), &Config{}),
	}
	if err := n.runConnect("tcp", listener.Addr().String()); err != nil {
		t.Errorf("failed to run connect: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("expected listener to accept connection, but it timed out")
	}
	if n.stdout.(*bytes.Buffer).String() != "test conn data" {
		t.Errorf("expected stdout to contain %q, got %q", "test conn data", n.stdout.(*bytes.Buffer).String())
	}
}

func Test_runConnect_ssl(t *testing.T) {
	tcases := []struct {
		name               string
		noVerify           bool
		validateServerName bool
		ciphers            []uint16
		alpn               []string
	}{
		{
			name:     "ssl no verify",
			noVerify: true,
		},
		{
			name:     "ssl verify",
			noVerify: false,
		},
		{
			name:               "ssl with server name",
			validateServerName: true,
		},
		{
			name:    "ssl with ciphers",
			ciphers: []uint16{tls.TLS_AES_128_GCM_SHA256},
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := tls.LoadX509KeyPair("testdata/test_cert.pem", "testdata/test_key.pem")
			if err != nil {
				t.Fatalf("failed to load test cert: %v", err)
			}
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{cert},
			})
			if err != nil {
				t.Errorf("failed to start test server: %v", err)
			}
			defer listener.Close()

			done := make(chan error, 1)
			go func() {
				var listenerErr error
				defer func() {
					done <- listenerErr
				}()

				conn, err := listener.Accept()
				if err != nil {
					listenerErr = err
					return
				}
				defer conn.Close()

				tlsConn, ok := conn.(*tls.Conn)
				if !ok {
					listenerErr = fmt.Errorf("expected tls.Conn, got %T", conn)
					return
				}
				if err := tlsConn.Handshake(); err != nil {
					listenerErr = err
					return
				}
				if len(tc.ciphers) > 0 && !slices.Contains(tc.ciphers, tlsConn.ConnectionState().CipherSuite) {
					listenerErr = fmt.Errorf("expected cipher %v, got %v", tc.ciphers, tlsConn.ConnectionState().CipherSuite)
					return
				}

				if _, err := conn.Write([]byte("test conn data")); err != nil {
					listenerErr = err
					return
				}
				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil {
					listenerErr = err
					return
				}
				if string(buf[:n]) != "test stdin data" {
					listenerErr = fmt.Errorf("expected 'test stdin data', got %q", string(buf[:n]))
				}
			}()

			time.Sleep(100 * time.Millisecond) // Give the listener a moment to start

			n := &netcat{
				stdin:  bytes.NewBufferString("test stdin data"),
				stdout: &bytes.Buffer{},
				cfg: &Config{
					NetcatMode:  NetcatModeConnect,
					Socket:      SocketTCP,
					Host:        "localhost",
					UseSSL:      true,
					SSLNoVerify: tc.noVerify,
				},
				log: NewLogger(log.New(io.Discard, "", 0), &Config{}),
			}

			// Extract port from listener address
			port := strings.Split(listener.Addr().String(), ":")[1]
			intPort, _ := strconv.Atoi(port)
			n.cfg.Port = uint16(intPort)

			if !tc.noVerify {
				n.cfg.SSLTrustFile = "testdata/test_cert.pem" // Set the SSL trust file to the self-signed cert
			}

			if tc.validateServerName {
				// Set the host to the loopback address and validate the CN in testdata/test_cert.pem (localhost)
				n.cfg.Host = "127.0.0.1"
				n.cfg.ServerName = "localhost"
			}

			if tc.ciphers != nil {
				n.cfg.SSLCiphers = tc.ciphers
			}

			addr, _ := n.cfg.Address()
			if err := n.runConnect("tcp", addr); err != nil {
				t.Errorf("failed to run connect: %v", err)
			}

			select {
			case err := <-done:
				if err != nil {
					t.Errorf("test listener error: %v", err)
				}
			case <-time.After(1 * time.Second):
				t.Error("expected listener to accept connection, but it timed out")
			}
			if n.stdout.(*bytes.Buffer).String() != "test conn data" {
				t.Errorf("expected stdout to contain %q, got %q", "test conn data", n.stdout.(*bytes.Buffer).String())
			}
		})
	}
}

func Test_runConnect_unix(t *testing.T) {
	socket := os.TempDir() + "/gonc_test.sock"
	t.Cleanup(func() {
		_ = os.Remove(socket) // Clean up after test
	})

	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Errorf("failed to start test server: %v", err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() {
		var listenerErr error
		defer func() {
			done <- listenerErr
		}()

		conn, err := listener.Accept()
		if err != nil {
			listenerErr = err
			return
		}
		defer conn.Close()

		if _, err := conn.Write([]byte("test conn data")); err != nil {
			listenerErr = err
			return
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			listenerErr = err
			return
		}
		if string(buf[:n]) != "test stdin data" {
			listenerErr = fmt.Errorf("expected 'test stdin data', got %q", string(buf[:n]))
		}
	}()

	n := &netcat{
		stdin:  bytes.NewBufferString("test stdin data"),
		stdout: &bytes.Buffer{},
		cfg: &Config{
			NetcatMode: NetcatModeConnect,
			Socket:     SocketUnix,
		},
		log: NewLogger(log.New(io.Discard, "", 0), &Config{}),
	}
	if err := n.runConnect("unix", listener.Addr().String()); err != nil {
		t.Fatalf("failed to run connect: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("expected listener to accept connection, but it timed out")
	}
	if n.stdout.(*bytes.Buffer).String() != "test conn data" {
		t.Errorf("expected stdout to contain %q, got %q", "test conn data", n.stdout.(*bytes.Buffer).String())
	}
}

func Test_runConnect_udp(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Errorf("failed to start test server: %v", err)
	}
	defer conn.Close()

	done := make(chan error, 1)
	go func() {
		var listenerErr error
		defer func() {
			done <- listenerErr
		}()

		buf := make([]byte, 1024)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			listenerErr = err
			return
		}
		if string(buf[:n]) != "test stdin data" {
			listenerErr = fmt.Errorf("expected 'test stdin data', got %q", string(buf[:n]))
		}
		if _, err := conn.WriteTo([]byte("test conn data"), addr); err != nil {
			listenerErr = err
		}
	}()

	n := &netcat{
		stdin:  bytes.NewBufferString("test stdin data"),
		stdout: &bytes.Buffer{},
		cfg: &Config{
			NetcatMode: NetcatModeConnect,
			Socket:     SocketUDP,
		},
		log: NewLogger(log.New(io.Discard, "", 0), &Config{}),
	}
	if err := n.runConnect(n.cfg.Network(), conn.LocalAddr().String()); err != nil {
		t.Fatalf("failed to run connect: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("test server timed out")
	}
	if n.stdout.(*bytes.Buffer).String() != "test conn data" {
		t.Errorf("expected stdout to contain %q, got %q", "test conn data", n.stdout.(*bytes.Buffer).String())
	}
}

func Test_runConnect_unixgram(t *testing.T) {
	socket := os.TempDir() + "/gonc_test.sock"
	t.Cleanup(func() {
		_ = os.Remove(socket) // Clean up after test
	})

	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Net: "unixgram", Name: socket})
	if err != nil {
		t.Errorf("failed to start test server: %v", err)
	}
	defer conn.Close()

	done := make(chan error, 1)
	go func() {
		var listenerErr error
		defer func() {
			done <- listenerErr
		}()

		buf := make([]byte, 1024)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			listenerErr = err
			return
		}
		if string(buf[:n]) != "test stdin data" {
			listenerErr = fmt.Errorf("expected 'test stdin data', got %q", string(buf[:n]))
		}
		if _, err := conn.WriteTo([]byte("test conn data"), addr); err != nil {
			listenerErr = err
		}
	}()

	n := &netcat{
		stdin:  bytes.NewBufferString("test stdin data"),
		stdout: &bytes.Buffer{},
		cfg: &Config{
			NetcatMode: NetcatModeConnect,
			Socket:     SocketUnixgram,
		},
		log: NewLogger(log.New(io.Discard, "", 0), &Config{}),
	}
	if err := n.runConnect(n.cfg.Network(), conn.LocalAddr().String()); err != nil {
		t.Fatalf("failed to run connect: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("test server timed out")
	}
	if n.stdout.(*bytes.Buffer).String() != "test conn data" {
		t.Errorf("expected stdout to contain %q, got %q", "test conn data", n.stdout.(*bytes.Buffer).String())
	}
}

func Test_netcat_dial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Errorf("failed to start test server: %v", err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()

	logBuf := bytes.Buffer{}
	n := &netcat{
		cfg: &Config{
			NetcatMode: NetcatModeConnect,
			Socket:     SocketTCP,
		},
		log: NewLogger(log.New(&logBuf, "", 0), &Config{Verbose: true}),
	}
	conn, err := n.dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("expected listener to accept connection, but it timed out")
	}

	defer conn.Close()
}

func Test_netcat_runConnect_dialError(t *testing.T) {
	logBuf := &bytes.Buffer{}
	n := &netcat{
		cfg: &Config{
			NetcatMode: NetcatModeConnect,
			Socket:     SocketTCP,
		},
		log: NewLogger(log.New(logBuf, "", 0), &Config{Verbose: true}),
	}
	// Try to connect to a port that is not open
	err := n.runConnect("tcp", "127.0.0.1:0")
	if err == nil {
		t.Fatalf("expected error when connecting to closed port, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("dial")) {
		t.Errorf("expected error to contain 'dial', got %v", err)
	}
}

func Test_netcat_runConnect_connect(t *testing.T) {
	logBuf := &bytes.Buffer{}
	n := &netcat{
		stdin:  bytes.NewBufferString("test stdin data"),
		stdout: &bytes.Buffer{},
		cfg: &Config{
			ScanPorts:  false,
			NetcatMode: NetcatModeConnect,
			Socket:     SocketTCP,
		},
		log: NewLogger(log.New(logBuf, "", 0), &Config{Verbose: true}),
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer listener.Close()

	readRes := make([]byte, 1024)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("failed to accept connection: %v", err)
			return
		}
		defer conn.Close()

		if _, err = conn.Read(readRes); err != nil {
			t.Errorf("failed to read from connection: %v", err)
		}
		if _, err := conn.Write([]byte("response data")); err != nil {
			t.Errorf("failed to write to connection: %v", err)
		}
	}()

	err = n.runConnect("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(readRes[:15]) != "test stdin data" {
		t.Errorf("expected read to contain %q, got %q", "test stdin data", string(readRes[:15]))
	}
	if n.stdout.(*bytes.Buffer).String() != "response data" {
		t.Errorf("expected stdout to contain %q, got %q", "response data", n.stdout.(*bytes.Buffer).String())
	}
	expectedLog := fmt.Sprintf("Connection to %s [tcp] succeeded!\n", listener.Addr().String())
	if logBuf.String() != expectedLog {
		t.Errorf("expected log to contain %q, got %q", expectedLog, logBuf.String())
	}
}

func Test_netcat_connect_TCPSuccess(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer listener.Close()

	var readRes = make([]byte, 1024)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("failed to accept connection: %v", err)
		}
		defer conn.Close()

		nRead, err := conn.Read(readRes)
		if err != nil {
			t.Errorf("failed to read from connection: %v", err)
		}
		readRes = readRes[:nRead]
		if _, err = conn.Write([]byte("response data")); err != nil {
			t.Errorf("failed to write to connection: %v", err)
		}
	}()

	n := &netcat{
		stdin:  bytes.NewBufferString("stdin data"),
		stdout: &bytes.Buffer{},
		cfg: &Config{
			NetcatMode: NetcatModeConnect,
			Socket:     SocketTCP,
		},
		log: NewLogger(log.New(&bytes.Buffer{}, "", 0), &Config{Verbose: true}),
	}

	if err := n.connect("tcp", listener.Addr().String()); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	if string(readRes) != "stdin data" {
		t.Errorf("expected read to contain %q, got %q", "stdin data", string(readRes))
	}
	if n.stdout.(*bytes.Buffer).String() != "response data" {
		t.Errorf("expected stdout to contain %q, got %q", "response data", n.stdout.(*bytes.Buffer).String())
	}
}

func Test_netcat_portScan(t *testing.T) {
	var wg sync.WaitGroup
	ready := make(chan struct{}, 3)
	for i := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", 5000+i))
			if err != nil {
				log.Fatalf("failed to start test server: %v", err)
			}
			defer listener.Close()

			ready <- struct{}{} // signal that this listener is ready

			conn, err := listener.Accept()
			if err != nil {
				t.Errorf("failed to accept connection: %v", err)
			}
			defer conn.Close()
		}()
	}
	// Wait for all listeners to be ready
	for range 3 {
		<-ready
	}

	logBuf := &bytes.Buffer{}
	n := &netcat{
		cfg: &Config{
			NetcatMode: NetcatModeConnect,
			Socket:     SocketTCP,
			Host:       "127.0.0.1",
			Port:       5000,
			EndPort:    5002,
		},
		log: NewLogger(log.New(logBuf, "", 0), &Config{Verbose: true}),
	}
	err := n.portScan("tcp")
	if err != nil {
		t.Errorf("failed to scan ports: %v", err)
	}
	wg.Wait()

	if n.cfg.Port != 5003 {
		t.Errorf("expected port 5003, got %d", n.cfg.Port)
	}
	for i := 5000; i <= 5002; i++ {
		if !bytes.Contains(logBuf.Bytes(), fmt.Appendf(nil, "Connection to 127.0.0.1:%d succeeded!", i)) {
			t.Errorf("expected log to contain 'Connection to 127.0.0.1:%d succeeded', got %q", i, logBuf.String())
		}
	}
}
