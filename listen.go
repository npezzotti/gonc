package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

func (n *netcat) runListen(network, laddr string) error {
	listener, err := n.createListener(network, laddr)
	if err != nil {
		return fmt.Errorf("createListener: %w", err)
	}
	defer listener.Close()

	n.log.Verbose("Listening on %s", listener.Addr().String())

	if n.cfg.Socket.IsPacket() {
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

	if n.cfg.DebugSocket {
		if err := enableSocketDebug(conn); err != nil {
			return fmt.Errorf("enable socket debug: %w", err)
		}
	}

	return n.handleConn(conn)
}

func (n *netcat) acceptForever(listener net.Listener) error {
	for {
		if err := n.accept(listener); err != nil {
			return fmt.Errorf("accept: %w", err)
		}
	}
}

func (n *netcat) createListener(network, laddr string) (net.Listener, error) {
	switch n.cfg.Socket {
	case SocketUDP, SocketUnixgram:
		return NewUDPListener(network, laddr)
	case SocketTCP:
		if n.cfg.UseSSL {
			cert, err := tls.LoadX509KeyPair(n.cfg.SSLCert, n.cfg.SSLKey)
			if err != nil {
				return nil, fmt.Errorf("LoadX509KeyPair: %w", err)
			}

			return tls.Listen(network, laddr, &tls.Config{
				CipherSuites: n.cfg.SSLCiphers,
				Certificates: []tls.Certificate{cert},
			})
		}
		return net.Listen(network, laddr)
	case SocketUnix:
		return net.Listen(network, laddr)
	default:
		return nil, fmt.Errorf("unsupported socket type: %v", n.cfg.Socket)
	}
}

// acceptConn accepts a new connection from the listener.
// It sets the read and write buffers according to the configuration.
func (n *netcat) acceptConn(listener net.Listener) (net.Conn, error) {
	conn, err := listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept connection: %w", err)
	}

	if n.cfg.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
	}

	return conn, nil
}

func (n *netcat) handleConn(conn net.Conn) error {
	writeErrChan := make(chan error)
	if !n.cfg.NoStdin {
		go func() {
			_, err := io.Copy(newIdleTimeoutConn(conn, n.cfg.Timeout), n.stdin)
			if err == nil && n.cfg.ExitOnEOF {
				err = closeWrite(conn)
			}
			writeErrChan <- err
		}()
	}

	_, readErr := io.Copy(n.stdout, newIdleTimeoutConn(conn, n.cfg.Timeout))

	if !n.cfg.NoStdin {
		// Wait for stdin copying to finish
		writeErr := <-writeErrChan
		if writeErr != nil {
			return writeErr
		}
	}

	return readErr
}
