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

func (n *netcat) handleConn(conn net.Conn) error {
	writeErrChan := make(chan error)
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
	if n.cfg.Telnet && n.cfg.NetcatMode == NetcatModeConnect {
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
		// Wait for stdin copying to finish
		stdinErr := <-writeErrChan
		if stdinErr != nil {
			return stdinErr
		}
	}

	return readErr
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
			if err := conn.SetDeadline(time.Now().Add(n.cfg.Timeout)); err != nil {
				return fmt.Errorf("set deadline: %w", err)
			}
		}

		n.log.Verbose("Receiving packets from %s", remoteAddr.String())
	}

	var stdinDone = make(chan struct{})
	var writeErr error
	go func() {
		defer close(stdinDone)

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
				if err := conn.SetDeadline(time.Now().Add(n.cfg.Timeout)); err != nil {
					writeErr = fmt.Errorf("set deadline: %w", err)
					return
				}
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
readLoop:
	for {
		if nb > 0 {
			if _, err := n.stdout.Write(connBuff[:nb]); err != nil {
				readErr = err
				break
			}
		}

		// Check if stdin is done
		select {
		case <-stdinDone:
			break readLoop
		default:
		}

		if n.cfg.Timeout > 0 {
			if err := conn.SetDeadline(time.Now().Add(n.cfg.Timeout)); err != nil {
				readErr = fmt.Errorf("set deadline: %w", err)
				break
			}
		}

		var clientAddr net.Addr
		nb, clientAddr, err = conn.ReadFrom(connBuff)
		if err != nil {
			if !errors.Is(err, io.EOF) {
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

	<-stdinDone // wait for stdin goroutine to finish

	if writeErr != nil {
		return writeErr
	}
	return readErr
}
