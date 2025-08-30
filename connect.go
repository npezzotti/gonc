package main

import (
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

func (n *netcat) runConnect(network, remoteAddr string) error {
	if n.cfg.ScanPorts {
		return n.portScan(network)
	}

	return n.connect(network, remoteAddr)
}

func (n *netcat) connect(network, remoteAddr string) error {
	if n.cfg.Socket == SocketUnixgram && n.cfg.SourceHost == "" {
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

	if n.cfg.Socket.IsPacket() {
		return n.copyPackets(conn.(net.PacketConn))
	}

	var writeErrChan = make(chan error)
	if !n.cfg.NoStdin {
		if n.cfg.Interval > 0 {
			go func() {
				err := scanLinesWithInterval(conn, n.stdin, n.cfg.Interval)
				if err == nil && !n.cfg.NoShutdown {
					err = closeWrite(conn.(WriteCloser))
				}
				writeErrChan <- err
			}()
		} else {
			go func() {
				_, err := io.Copy(newIdleTimeoutConn(conn, n.cfg.Timeout), n.stdin)
				if err == nil && !n.cfg.NoShutdown {
					err = closeWrite(conn.(WriteCloser))
				}
				writeErrChan <- err
			}()
		}
	}

	var src io.Reader
	if n.cfg.Telnet {
		src = newTelnetConn(conn, n.cfg.Timeout)
	} else {
		src = newIdleTimeoutConn(conn, n.cfg.Timeout)
	}

	var readErr error
	if n.cfg.Interval > 0 {
		readErr = scanLinesWithInterval(n.stdout, src, n.cfg.Interval)
	} else {
		_, readErr = io.Copy(n.stdout, src)
	}

	if !n.cfg.NoStdin {
		stdinErr := <-writeErrChan
		if stdinErr != nil {
			return stdinErr
		}
	}

	return readErr
}

func (n *netcat) dial(network, remoteAddr string) (net.Conn, error) {
	if n.cfg.ProxyAddr != "" {
		// If a proxy is configured, use it
		return n.dialProxy(network, remoteAddr)
	}

	var dialer net.Dialer
	var err error

	switch n.cfg.Socket {
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

	if n.cfg.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
	}

	return conn, nil
}

func (n *netcat) portScan(network string) error {
	for n.cfg.Port <= n.cfg.EndPort {
		addr, err := n.cfg.Address()
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

		if n.cfg.Interval > 0 {
			time.Sleep(n.cfg.Interval)
		}
	}

	return nil
}
