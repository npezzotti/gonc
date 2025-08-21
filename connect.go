package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
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

type telnetConn struct {
	net.Conn
	timeout time.Duration
	buffer  bytes.Buffer
}

func (c *telnetConn) Read(b []byte) (int, error) {
	if c.buffer.Len() > 0 {
		return c.buffer.Read(b)
	}

	if c.timeout > 0 {
		if err := c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
			return 0, err
		}
	}

	// Read data into a temporary buffer to process telnet commands
	tmp := make([]byte, 2048)
	n, err := c.Conn.Read(tmp)
	if err != nil {
		return 0, err
	}

	c.processTelnet(tmp[:n], c)

	fmt.Println("exiting read")
	return c.buffer.Read(b)
}

func (c *telnetConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		c.Conn.SetDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Write(b)
}

func (n *netcat) runConnect(network, remoteAddr string) error {
	if n.cfg.ScanPorts {
		return n.portScan(network)
	}

	return n.connect(network, remoteAddr)
}

func (n *netcat) connect(network, remoteAddr string) error {
	if n.cfg.ProtocolConfig.Socket == SocketUnixgram && n.cfg.SourceHost == "" {
		// If using unixgram and no source host is specified, create a temporary socket file
		clientSocket := filepath.Join(os.TempDir(), fmt.Sprintf("gonc-%x.sock", rand.Uint64()))
		defer os.Remove(clientSocket)

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
		_, err := io.Copy(&idleTimeoutConn{Conn: conn, timeout: n.cfg.Timeout}, os.Stdin)
		if err == nil {
			if n.cfg.ExitOnEOF {
				closeWrite(conn)
			}
		} else {
			writeErr = err
		}
		writeErrChan <- writeErr
	}()

	var src io.Reader
	if n.cfg.Telnet {
		src = &telnetConn{Conn: conn, timeout: n.cfg.Timeout}
	} else {
		src = &idleTimeoutConn{Conn: conn, timeout: n.cfg.Timeout}
	}

	if _, err = io.Copy(os.Stdout, src); err != nil {
		return err
	}

	return <-writeErrChan
}

func closeWrite(conn net.Conn) error {
	if c, ok := conn.(*tls.Conn); ok && c.ConnectionState().HandshakeComplete {
		return c.CloseWrite()
	} else {
		return conn.(WriteCloser).CloseWrite()
	}
}

// processTelnet processes telnet commands in the given data.
// It returns the number of bytes processed as telnet commands.
func (c *telnetConn) processTelnet(data []byte, conn net.Conn) {
	fmt.Println("processing telnet")
	var i int
	for i < len(data) {
		if data[i] == IAC {
			command := data[i+1]
			option := data[i+2]

			switch command {
			case DO:
				fmt.Println("Processed DO command")
				// just respond with WON'T for any DO request
				conn.Write([]byte{IAC, WONT, option})
			case WILL:
				fmt.Println("Processed WILL command")
				// just respond with DON'T for any WILL request
				conn.Write([]byte{IAC, DONT, option})
			}

			i += 3
		} else {
			c.buffer.WriteByte(data[i])
			i++
		}
	}
	fmt.Println("exiting")
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

	if n.cfg.DebugSocket {
		if err := enableSocketDebug(conn); err != nil {
			return nil, fmt.Errorf("enable socket debug: %w", err)
		}
	}

	if n.cfg.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
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
