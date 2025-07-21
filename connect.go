package main

import (
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

func (n *netcat) runConnect() error {
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
	wg.Add(1)
	go func() {
		defer func() {
			conn.(HalfCloser).CloseWrite()
			n.log.Verbose("writer done")
			wg.Done()
		}()
		stdin := make(chan []byte)
		if !n.cfg.NoStdin {
			go func() {
				defer close(stdin)

				buf := make([]byte, 1024)
				for {
					nb, err := os.Stdin.Read(buf)
					if err != nil {
						isEOF := errors.Is(err, io.EOF)
						if !isEOF {
							n.log.Log("read stdin: %s", err)
						}

						if isEOF && !n.cfg.ExitOnEOF {
							continue
						}
						return
					}
					stdin <- buf[:nb]
				}
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
				// Reset the deadline on each write
				if n.cfg.Timeout > 0 {
					conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer func() {
			close(stop) // signal the writer goroutine to stop
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

	wg.Wait()
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
