package main

import (
	"crypto/tls"
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

	n.log.Verbose("Listening on %s", listener.Addr().String())

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
	switch n.cfg.ProtocolConfig.Socket {
	case SocketUDP, SocketUnixgram:
		return NewUDPListener(network, laddr)
	case SocketTCP:
		if n.cfg.UseSSL {
			cert, err := tls.LoadX509KeyPair(n.cfg.SSLCert, n.cfg.SSLKey)
			if err != nil {
				return nil, fmt.Errorf("LoadX509KeyPair: %w", err)
			}

			return tls.Listen(network, laddr, &tls.Config{
				InsecureSkipVerify: !n.cfg.SSLVerify,
				CipherSuites:       n.cfg.SSLCiphers,
				Certificates:       []tls.Certificate{cert},
			})
		}
		return net.Listen(network, laddr)
	case SocketUnix:
		return net.Listen(network, laddr)
	default:
		return nil, fmt.Errorf("unsupported socket type: %v", n.cfg.ProtocolConfig.Socket)
	}
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

	if n.cfg.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
	}

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
					if c, ok := conn.(*tls.Conn); ok && c.ConnectionState().HandshakeComplete {
						writeErr = c.CloseWrite()
					} else {
						writeErr = conn.(HalfCloser).CloseWrite()
					}
				} else {
					writeErr = err
				}
				break
			}

			if _, err := conn.Write(buf[:nr]); err != nil {
				writeErr = err
				break
			}

			if n.cfg.Timeout > 0 {
				conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
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

		if n.cfg.Timeout > 0 {
			conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
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
