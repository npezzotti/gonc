package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

type netcat struct {
	stdin  io.Reader
	stdout io.Writer
	cfg    *Config
	log    *Logger
}

type WriteCloser interface {
	CloseWrite() error
}

func scanLinesWithInterval(dst io.Writer, src io.Reader, interval time.Duration) error {
	scanner := bufio.NewScanner(src)
	var writeErr error
	firstLine := true
	for scanner.Scan() {
		if !firstLine {
			time.Sleep(interval)
		} else {
			firstLine = false
		}

		_, err := dst.Write(append(scanner.Bytes(), '\n'))
		if err != nil {
			writeErr = err
			break
		}
	}

	scanErr := scanner.Err()
	if scanErr != nil {
		writeErr = scanErr
	}

	return writeErr
}

func closeWrite(writeCloser WriteCloser) error {
	switch c := writeCloser.(type) {
	case *tls.Conn:
		// Ensure TLS handshake is complete before closing
		if c.ConnectionState().HandshakeComplete {
			return c.CloseWrite()
		}
		return fmt.Errorf("cannot CloseWrite on TLS connection before handshake is complete")
	default:
		return writeCloser.CloseWrite()
	}
}

func (n *netcat) copyPackets(conn net.PacketConn) error {
	var (
		remoteAddr net.Addr
		err        error
		nb         int
		connBuff   = make([]byte, 1024)
	)

	if n.cfg.NetcatMode == NetcatModeListen {
		// Listen for incoming packets and set the remote address before starting the writer.
		// This is necessary for gonc to simulate a peer-to-peer connection when using a connection-less protocol.
		nb, remoteAddr, err = conn.ReadFrom(connBuff)
		if err != nil {
			return err
		}

		if n.cfg.Timeout > 0 {
			conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
		}

		n.log.Verbose("Receiving packets from %s", remoteAddr.String())
	}

	var writeErr error
	go func() {
		defer conn.Close() // unblock read

		stdinBuf := make([]byte, 1024)
		for {
			nb, err := n.stdin.Read(stdinBuf)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					writeErr = err
				}
				return
			}

			if n.cfg.Timeout > 0 {
				conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
			}

			if n.cfg.NetcatMode == NetcatModeListen {
				// If in listen mode, write to the remote address
				if _, err = conn.WriteTo(stdinBuf[:nb], remoteAddr); err != nil {
					writeErr = err
					return
				}
			} else {
				// Otherwise, write to the connection directly
				if _, err = conn.(net.Conn).Write(stdinBuf[:nb]); err != nil {
					writeErr = err
					return
				}
			}
		}
	}()

	var readErr error
	for {
		if nb > 0 {
			if _, err := n.stdout.Write(connBuff[:nb]); err != nil {
				readErr = err
				break
			}
		}

		if n.cfg.Timeout > 0 {
			conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
		}

		var clientAddr net.Addr
		nb, clientAddr, err = conn.ReadFrom(connBuff)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				readErr = err
			}
			break
		}

		if n.cfg.NetcatMode == NetcatModeListen && nb > 0 && clientAddr.String() != remoteAddr.String() {
			// drop packets from other clients
			nb = 0
			continue
		}
	}

	if writeErr != nil {
		return writeErr
	}
	return readErr
}
