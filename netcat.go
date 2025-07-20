package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type netcat struct {
	cfg      *Config
	log      *Logger
	shutdown chan struct{}
}

type HalfCloser interface {
	CloseRead() error
	CloseWrite() error
}

func (n *netcat) connect() error {
	// Create a client
	var dialer net.Dialer
	var err error

	if n.cfg.ProtocolConfig.Socket == SocketUnixgram && n.cfg.SourceHost == "" {
		clientSocket := filepath.Join(os.TempDir(), fmt.Sprintf("nc-%x.sock", rand.Uint64()))
		defer os.Remove(clientSocket) // Clean up the socket file after use

		n.cfg.SourceHost = clientSocket
	}

	switch n.cfg.ProtocolConfig.Socket {
	case SocketUnix:
		dialer.LocalAddr, err = net.ResolveUnixAddr("unix", n.cfg.SourceHost)
		if err != nil {
			return fmt.Errorf("resolve unix addr: %w", err)
		}
	case SocketUnixgram:
		dialer.LocalAddr, err = net.ResolveUnixAddr("unixgram", n.cfg.SourceHost)
		if err != nil {
			return fmt.Errorf("resolve unix addr: %w", err)
		}
	case SocketTCP:
		dialer.LocalAddr, err = net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", n.cfg.SourceHost, n.cfg.SourcePort))
		if err != nil {
			return fmt.Errorf("resolve tcp addr: %w", err)
		}
	case SocketUDP:
		dialer.LocalAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", n.cfg.SourceHost, n.cfg.SourcePort))
		if err != nil {
			return fmt.Errorf("resolve udp addr: %w", err)
		}
	}

	if n.cfg.ConnTimeout > 0 {
		dialer.Timeout = n.cfg.ConnTimeout
	}

	// if scanning ports, exit here
	if n.cfg.ScanPorts {
		return n.portScan(dialer)
	}

	// connect
	remoteAddr, err := n.cfg.ParseAddress()
	if err != nil {
		return fmt.Errorf("get address: %w", err)
	}
	conn, err := dialer.Dial(n.cfg.ProtocolConfig.Network(), remoteAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	n.log.Verbose("Connected to %s\n", conn.RemoteAddr().String())

	setReceiveBuffer(conn, n.cfg.RecvBuf)
	setSendBuffer(conn, n.cfg.SendBuf)

	if n.cfg.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
	}

	network := n.cfg.ProtocolConfig.Network()
	if network == "udp" ||
		network == "udp4" ||
		network == "udp6" ||
		network == "unixgram" {
		return copyPackets(conn.(net.PacketConn), false)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	if !n.cfg.NoStdin {
		wg.Add(1)
		go func() {
			defer func() {
				conn.(HalfCloser).CloseWrite()
				n.log.Verbose("writer done")
				wg.Done()
			}()
			stdin := make(chan []byte)
			go func() {
				buf := make([]byte, 1024)
				for {
					nb, err := os.Stdin.Read(buf)
					if err != nil {
						if err != io.EOF {
							n.log.Log("read stdin: %s", err)
						}
						break
					}
					stdin <- buf[:nb]
				}
				close(stdin)
			}()

			for {
				select {
				case <-stop:
					return // signal received, exit writer
				case data, ok := <-stdin:
					if !ok {
						return // stdin closed, exit writer
					}
					if _, err := conn.Write(data); err != nil {
						n.log.Log("write to conn: %s", err)
						return
					}
					// Reset the deadline on each write
					if n.cfg.Timeout > 0 {
						conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
					}
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer func() {
			// close(stop)
			n.log.Verbose("reader done")
			wg.Done()
		}()

		for {
			buf := make([]byte, 1024)
			nb, err := conn.Read(buf)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					n.log.Log("read conn: %s", err)
				}
				return
			}

			if _, err := os.Stdout.Write(buf[:nb]); err != nil {
				n.log.Log("write stdout: %s", err)
				return
			}

			if n.cfg.Timeout > 0 {
				conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
			}
		}
	}()

	doneChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneChan)
	}()

	fmt.Println("waiting for shutdown signal...")
	select {
	case <-n.shutdown:
		conn.Close()
		close(stop)
		<-doneChan // wait for the goroutines to finish
	case <-doneChan:
	}

	return nil
}

func (n *netcat) portScan(dialer net.Dialer) error {
	currentPort := n.cfg.StartPort
	for currentPort <= n.cfg.EndPort {
		conn, err := dialer.Dial(n.cfg.ProtocolConfig.Network(), net.JoinHostPort(n.cfg.Host, fmt.Sprintf("%d", currentPort)))
		if err != nil {
			n.log.Log("dial tcp: %s\n", err)
			currentPort++
			continue
		}

		n.log.Verbose("Connection to %s port %d succeeded!\n", n.cfg.Host, currentPort)

		if err := conn.Close(); err != nil {
			n.log.Log("error closing connection: %s", err)
		}

		currentPort++
	}

	return nil
}

func (n *netcat) listen() error {
	var (
		err      error
		listener net.Listener
	)

	localAddr, err := n.cfg.ParseAddress()
	if err != nil {
		return fmt.Errorf("get address: %w", err)
	}
	switch n.cfg.ProtocolConfig.Network() {
	case "udp", "udp4", "udp6", "unixgram":
		listener, err = NewDatagramListener(n.cfg.ProtocolConfig.Network(), localAddr)
		if err != nil {
			return fmt.Errorf("create datagram listener: %w", err)
		}
	case "tcp", "tcp4", "tcp6", "unix":
		listener, err = net.Listen(n.cfg.ProtocolConfig.Network(), localAddr)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
	}
	defer listener.Close()

	n.log.Verbose("Listening on %s", listener.Addr().String())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		close(n.shutdown) // signal shutdown
	}()

	return n.acceptConn(listener)
}

func (n *netcat) handleConn(conn net.Conn) error {
	network := n.cfg.ProtocolConfig.Network()
	if network == "udp" ||
		network == "udp4" ||
		network == "udp6" ||
		network == "unixgram" {
		return copyPackets(conn.(net.PacketConn), true)
	}

	addr := conn.RemoteAddr().String()
	if addr == "" {
		addr = conn.LocalAddr().String()
	}
	n.log.Verbose("Connection received on %s\n", addr)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer func() {
			conn.(HalfCloser).CloseWrite()
			n.log.Verbose("writer done")
			wg.Done()
		}()

		stdin := make(chan []byte)
		if !n.cfg.NoStdin {
			// Read from stdin in a separate goroutine
			go func() {
				buf := make([]byte, 1024)
				for {
					nb, err := os.Stdin.Read(buf)
					if err != nil {
						if !errors.Is(err, io.EOF) {
							n.log.Log("read stdin: %s", err)
						}
						break
					}
					stdin <- buf[:nb]
				}
				close(stdin)
			}()
		}

		for {
			select {
			case <-stop:
				return // signal received, exit writer
			case data, ok := <-stdin:
				if !ok {
					return // stdin closed, exit writer
				}
				if _, err := conn.Write(data); err != nil {
					n.log.Log("write to conn: %s", err)
					return
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer func() {
			// close(stop)
			n.log.Verbose("reader done")
			wg.Done()
		}()

		for {
			buf := make([]byte, 1024)
			nb, err := conn.Read(buf)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					n.log.Log("read conn: %s", err)
				}
				return
			}

			if _, err := os.Stdout.Write(buf[:nb]); err != nil {
				n.log.Log("write stdout: %s", err)
				return
			}

			if n.cfg.Timeout > 0 {
				conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
			}
		}
	}()

	doneChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneChan)
	}()

	select {
	case <-n.shutdown:
		conn.Close()
		// Signal the writer goroutine to stop (if running)
		close(stop)
		// Wait for both goroutines to finish
		<-doneChan
	case <-doneChan:
	}

	return nil
}

func (n *netcat) acceptConn(listener net.Listener) error {
	for {
		select {
		case <-n.shutdown:
			return nil
		default:
			errChan := make(chan error, 1)
			connChan := make(chan net.Conn, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					errChan <- fmt.Errorf("accept connection: %w", err)
					return
				}
				connChan <- conn
			}()

			var conn net.Conn
			select {
			case <-n.shutdown:
				return nil
			case err := <-errChan:
				return err
			case conn = <-connChan:
			}
			defer conn.Close()

			if n.cfg.Timeout > 0 {
				conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
			}

			setReceiveBuffer(conn, n.cfg.RecvBuf)
			setSendBuffer(conn, n.cfg.SendBuf)

			if err := n.handleConn(conn); err != nil {
				n.log.Log("handle connection: %s", err)
			}

			if !n.cfg.KeepListening {
				return nil // exit after handling one connection
			}
		}
	}
}

func copyPackets(conn net.PacketConn, listen bool) error {
	var wg sync.WaitGroup
	var remoteAddr net.Addr
	var err error
	var n int

	if listen {
		buf := make([]byte, 1024)
		n, remoteAddr, err = conn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("read from conn: %w", err)
		}

		log.Printf("Receiving packets from %s\n", remoteAddr.String())

		if _, err := os.Stdout.Write(buf[:n]); err != nil {
			log.Printf("write stdout: %s\n", err)
			return err
		}
	}

	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer func() {
			conn.Close() // Close the connection to signal the reader goroutine to stop.
			wg.Done()
		}()

		stdin := make(chan []byte)
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := os.Stdin.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Printf("read stdin: %s\n", err)
					}
					break
				}
				stdin <- buf[:n]
			}
			close(stdin)
		}()

		for {
			select {
			case data, ok := <-stdin:
				if !ok {
					return
				}
				if listen {
					if _, err = conn.WriteTo(data, remoteAddr); err != nil {
						if !errors.Is(err, net.ErrClosed) {
							log.Printf("write to: %s", err)
						}
						return
					}
				} else {
					_, err = conn.(net.Conn).Write(data)
					if err != nil {
						log.Printf("write: %s", err)
						return
					}
				}
			case <-stop:
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
		}()

		buf := make([]byte, 1024)
		for {
			select {
			case <-stop:
				return
			default:
				n, clientAddr, err := conn.ReadFrom(buf)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						log.Printf("read from conn: %s", err)
					}
					return
				}

				if listen && clientAddr.String() != remoteAddr.String() {
					// drop packets from other clients
					continue
				}

				if _, err := os.Stdout.Write(buf[:n]); err != nil {
					log.Printf("write stdout: %s", err)
					return
				}
			}
		}
	}()

	doneChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneChan) // Close the channel to signal that all goroutines are done.
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		close(stop) // signal the writer goroutine to stop
		<-doneChan  // wait for the goroutines to finish
	case <-doneChan:
	}

	return nil
}

func setSendBuffer(conn net.Conn, size int) error {
	if size > 0 {
		switch c := conn.(type) {
		case *net.UDPConn:
			return c.SetWriteBuffer(size)
		case *net.TCPConn:
			return c.SetWriteBuffer(size)
		case *net.UnixConn:
			return c.SetWriteBuffer(size)
		default:
			return fmt.Errorf("unsupported connection type for setting send buffer: %T", conn)
		}
	}
	return nil
}

func setReceiveBuffer(conn net.Conn, size int) error {
	if size > 0 {
		switch c := conn.(type) {
		case *net.UDPConn:
			return c.SetReadBuffer(size)
		case *net.TCPConn:
			return c.SetReadBuffer(size)
		case *net.UnixConn:
			return c.SetReadBuffer(size)
		default:
			return fmt.Errorf("unsupported connection type for setting receive buffer: %T", conn)
		}
	}

	return nil
}
