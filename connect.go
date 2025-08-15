package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Telnet command constants
const (
	WILL = 251 // WILL
	WONT = 252 // WON'T
	DO   = 253 // DO
	DONT = 254 // DON'T
	IAC  = 255 // Interpret As Command
)

func (n *netcat) runConnect(network, remoteAddr string) error {
	if n.cfg.ScanPorts {
		return n.portScan(network)
	}

	return n.connect(network, remoteAddr)
}

func (n *netcat) connect(network, remoteAddr string) error {
	if n.cfg.ProtocolConfig.Socket == SocketUnixgram && n.cfg.SourceHost == "" {
		clientSocket := filepath.Join(os.TempDir(), fmt.Sprintf("gonc-%x.sock", rand.Uint64()))
		defer os.Remove(clientSocket) // Clean up the socket file after use

		n.cfg.SourceHost = clientSocket
	}

	conn, err := n.dial(network, remoteAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	n.log.Verbose("Connection to %s [%s] succeeded!", conn.RemoteAddr().String(), network)

	if n.cfg.ProtocolConfig.Socket.IsPacket() {
		return n.copyPackets(conn.(net.PacketConn))
	}

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

			if _, err = conn.Write(buf[:nr]); err != nil {
				writeErr = err
				break
			}

			if n.cfg.Timeout > 0 {
				conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
			}
		}
		writeErrChan <- writeErr
	}()

	buf := make([]byte, 1024)
	for {
		nb, err := conn.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return err
			}
			break
		}

		if n.cfg.Telnet {
			tn, err := processTelnet(buf[:nb], conn)
			if err != nil {
				return fmt.Errorf("process telnet: %w", err)
			}

			if tn > 0 {
				// if we processed telnet commands, extend the deadline and continue
				if n.cfg.Timeout > 0 {
					conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
				}

				continue
			}
		}

		if _, err := os.Stdout.Write(buf[:nb]); err != nil {
			return err
		}

		if n.cfg.Timeout > 0 {
			conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
		}
	}

	return <-writeErrChan
}

func processTelnet(data []byte, conn net.Conn) (int, error) {
	if len(data) < 3 {
		return 0, nil // Not enough data to process
	}

	if data[0] == IAC {
		command := data[1]
		option := data[2]

		switch command {
		case DO:
			// just respond with WON'T for any DO request
			return conn.Write([]byte{IAC, WONT, option})
		case WILL:
			// just respond with DON'T for any WILL request
			return conn.Write([]byte{IAC, DONT, option})
		}
	}

	return 0, nil // Return the data after the command
}

func (n *netcat) dial(network, remoteAddr string) (net.Conn, error) {
	if n.cfg.ProxyAddr != "" {
		// If a proxy is configured, use it
		return n.dialProxy(network, remoteAddr)
	}

	var dialer net.Dialer
	var err error

	switch n.cfg.ProtocolConfig.Socket {
	case SocketTCP:
		dialer.LocalAddr, err = net.ResolveTCPAddr(network, fmt.Sprintf("%s:%d", n.cfg.SourceHost, n.cfg.SourcePort))
		if err != nil {
			return nil, fmt.Errorf("resolve tcp addr: %w", err)
		}
	case SocketUDP:
		dialer.LocalAddr, err = net.ResolveUDPAddr(network, fmt.Sprintf("%s:%d", n.cfg.SourceHost, n.cfg.SourcePort))
		if err != nil {
			return nil, fmt.Errorf("resolve udp addr: %w", err)
		}
	case SocketUnix:
		dialer.LocalAddr, err = net.ResolveUnixAddr(network, n.cfg.SourceHost)
		if err != nil {
			return nil, fmt.Errorf("resolve unix addr: %w", err)
		}
	case SocketUnixgram:
		dialer.LocalAddr, err = net.ResolveUnixAddr(network, n.cfg.SourceHost)
		if err != nil {
			return nil, fmt.Errorf("resolve unix addr: %w", err)
		}
	}

	if n.cfg.Timeout > 0 {
		dialer.Timeout = n.cfg.Timeout
	}

	var conn net.Conn
	if n.cfg.UseSSL {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: n.cfg.SSLNoVerify,
			CipherSuites:       n.cfg.SSLCiphers,
			ServerName:         n.cfg.ServerName,
		}

		if n.cfg.SSLAlpn != nil {
			tlsConfig.NextProtos = n.cfg.SSLAlpn
		}

		if n.cfg.SSLTrustFile != "" {
			certPool := x509.NewCertPool()
			certData, err := os.ReadFile(n.cfg.SSLTrustFile)
			if err != nil {
				return nil, fmt.Errorf("read SSL trust file: %w", err)
			}
			if !certPool.AppendCertsFromPEM(certData) {
				return nil, fmt.Errorf("append certs from PEM: %w", err)
			}
			tlsConfig.RootCAs = certPool
		}

		conn, err = tls.DialWithDialer(&dialer, network, remoteAddr, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("dial with SSL: %w", err)
		}
	} else {
		conn, err = dialer.Dial(network, remoteAddr)
		if err != nil {
			return nil, err
		}
	}

	return conn, nil
}

func (n *netcat) portScan(network string) error {
	for n.cfg.Port <= n.cfg.EndPort {
		addr, err := n.cfg.ParseAddress()
		if err != nil {
			return fmt.Errorf("parse address: %w", err)
		}

		conn, err := n.dial(network, addr)
		if err != nil {
			n.log.Log("dial tcp: %s", err)
			n.cfg.Port++
			continue
		}

		n.log.Verbose("Connection to %s succeeded!", addr)

		conn.Close()
		n.cfg.Port++
	}

	return nil
}
