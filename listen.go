package main

import (
	"crypto/tls"
	"fmt"
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

	if n.cfg.KeepListening && !n.cfg.Socket.IsPacket() {
		return n.acceptForever(listener)
	}
	return n.accept(listener)
}

func (n *netcat) accept(listener net.Listener) error {
	conn, err := n.acceptConn(listener)
	if err != nil {
		return fmt.Errorf("acceptConn: %w", err)
	}
	defer conn.Close()

	if n.cfg.Socket.IsPacket() {
		return n.copyPackets(conn.(net.PacketConn))
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
				NextProtos:   n.cfg.SSLAlpn,
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
		if err := conn.SetDeadline(time.Now().Add(n.cfg.Timeout)); err != nil {
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}

	addr := conn.RemoteAddr()
	if addr != nil {
		if addr.String() == "" {
			// Unix socket connections may not have a remote address
			addr = conn.LocalAddr()
		}
		n.log.Verbose("Connection received on %s", addr.String())
	}

	return conn, nil
}
