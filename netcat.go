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

func closeWrite(conn net.Conn) error {
	switch c := conn.(type) {
	case *tls.Conn:
		if c.ConnectionState().HandshakeComplete {
			return c.CloseWrite()
		}
	default:
		if writeCloser, ok := c.(WriteCloser); ok {
			return writeCloser.CloseWrite()
		}
	}
	return fmt.Errorf("unsupported connection type: %T", conn)
}

func (n *netcat) copyPackets(conn net.PacketConn) error {
	var (
		remoteAddr net.Addr
		err        error
		nb         int
		connBuff   = make([]byte, 1024)
	)

	if n.cfg.NetcatMode == NetcatModeListen && !n.cfg.KeepListening {
		nb, remoteAddr, err = conn.ReadFrom(connBuff)
		if err != nil {
			return fmt.Errorf("read from: %w", err)
		}

		if n.cfg.Timeout > 0 {
			conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
		}

		n.log.Verbose("Receiving packets from %s", remoteAddr.String())
	}

	var writeErrChan = make(chan error, 1)
	go func() {
		defer conn.Close()

		var writeErr error
		stdinBuf := make([]byte, 1024)
		for {
			nb, err := n.stdin.Read(stdinBuf)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					writeErr = fmt.Errorf("read stdin: %w", err)
				}
				break
			}

			if n.cfg.NetcatMode == NetcatModeListen {
				// If in listen mode, write to the remote address
				if _, err = conn.WriteTo(stdinBuf[:nb], remoteAddr); err != nil {
					writeErr = fmt.Errorf("write to: %w", err)
					break
				}
			} else {
				// Otherwise, write to the connection directly
				if _, err = conn.(net.Conn).Write(stdinBuf[:nb]); err != nil {
					writeErr = fmt.Errorf("write: %w", err)
					break
				}
			}

			if n.cfg.Timeout > 0 {
				conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
			}
		}

		writeErrChan <- writeErr
	}()

	for {
		if nb > 0 {
			if _, err := n.stdout.Write(connBuff[:nb]); err != nil {
				return fmt.Errorf("write stdout: %w", err)
			}
		}

		var clientAddr net.Addr
		nb, clientAddr, err = conn.ReadFrom(connBuff)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("read from: %w", err)
			}
			break
		}

		if n.cfg.Timeout > 0 {
			conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
		}

		if n.cfg.NetcatMode == NetcatModeListen && clientAddr.String() != remoteAddr.String() {
			// drop packets from other clients
			nb = 0
			continue
		}
	}

	return <-writeErrChan
}
