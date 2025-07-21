package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

func (n *netcat) runListen() error {
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
		listener, err = NewUDPListener(n.cfg.ProtocolConfig.Network(), localAddr)
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

	return n.acceptConn(listener)
}

func (n *netcat) acceptConn(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept connection: %w", err)
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
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer func() {
			close(stop)
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
