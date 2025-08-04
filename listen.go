package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func (n *netcat) runListen(network, laddr string) error {
	listener, err := n.createListener(network, laddr)
	if err != nil {
		return fmt.Errorf("createListener: %w", err)
	}
	defer listener.Close()

	if n.cfg.ProtocolConfig.Socket.IsPacket() {
		return n.acceptUDP(listener)
	}

	if n.cfg.KeepListening {
		return n.acceptForever(listener)
	}
	return n.accept(listener)
}

func (n *netcat) acceptUDP(listener net.Listener) error {
	conn, err := n.acceptConn(listener)
	if err != nil {
		return fmt.Errorf("acceptConn: %w", err)
	}
	defer conn.Close()

	return n.copyPackets(conn.(net.PacketConn))
}

func (n *netcat) accept(listener net.Listener) error {
	conn, err := n.acceptConn(listener)
	if err != nil {
		return fmt.Errorf("acceptConn: %w", err)
	}
	defer conn.Close()

	addr := conn.RemoteAddr().String()
	if addr == "" {
		// Unix socket connections may not have a remote address
		addr = conn.LocalAddr().String()
	}
	n.log.Verbose("Connection received on %s", addr)

	return n.handleConn(conn)
}

func (n *netcat) acceptForever(listener net.Listener) error {
	for {
		if err := n.accept(listener); err != nil {
			return fmt.Errorf("listen: %w", err)
		}
	}
}

func (n *netcat) createListener(network, laddr string) (net.Listener, error) {
	var (
		listener net.Listener
		err      error
	)

	switch network {
	case "udp", "udp4", "udp6", "unixgram":
		listener, err = NewUDPListener(network, laddr)
		if err != nil {
			return nil, fmt.Errorf("create datagram listener: %w", err)
		}
	case "tcp", "tcp4", "tcp6", "unix":
		listener, err = net.Listen(network, laddr)
		if err != nil {
			return nil, fmt.Errorf("listen: %w", err)
		}
	}

	n.log.Verbose("Listening on %s", listener.Addr().String())

	return listener, nil
}

// acceptConn accepts a new connection from the listener.
// It sets the read and write buffers according to the configuration.
func (n *netcat) acceptConn(listener net.Listener) (net.Conn, error) {
	conn, err := listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept connection: %w", err)
	}

	setReadBuffer(conn, n.cfg.RecvBuf)
	setWriteBuffer(conn, n.cfg.SendBuf)

	return conn, nil
}

func (n *netcat) handleConn(conn net.Conn) error {
	writeErrChan := make(chan error)
	go func() {
		var writeErr error
		buf := make([]byte, 1024)
		for {
			nr, err := os.Stdin.Read(buf)
			if err != nil {
				if errors.Is(err, io.EOF) {
					writeErr = conn.(HalfCloser).CloseWrite()
				} else {
					writeErr = err
				}
				break
			}

			if _, err := conn.Write(buf[:nr]); err != nil {
				writeErr = err
				break
			}

			if n.cfg.IdleTimeout > 0 {
				conn.SetDeadline(time.Now().Add(n.cfg.IdleTimeout))
			}
		}
		writeErrChan <- writeErr
	}()

	var readErr error
	buf := make([]byte, 1024)
	for {
		nr, err := conn.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
				break
			}
			return nil // EOF is expected when the connection is closed by the other side
		}

		if n.cfg.IdleTimeout > 0 {
			conn.SetDeadline(time.Now().Add(n.cfg.IdleTimeout))
		}

		if _, err := os.Stdout.Write(buf[:nr]); err != nil {
			readErr = err
			break
		}
	}

	if readErr != nil {
		return readErr
	}

	return <-writeErrChan
}
