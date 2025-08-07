package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type netcat struct {
	cfg *Config
	log *Logger
}

type HalfCloser interface {
	CloseRead() error
	CloseWrite() error
}

func (n *netcat) copyPackets(conn net.PacketConn) error {
	var (
		remoteAddr net.Addr
		err        error
		nb         int
		connBuff   = make([]byte, 1024)
	)

	if n.cfg.NetcatMode == NetcatModeListen {
		nb, remoteAddr, err = conn.ReadFrom(connBuff)
		if err != nil {
			return fmt.Errorf("read from: %w", err)
		}

		if n.cfg.Timeout > 0 {
			conn.SetDeadline(time.Now().Add(n.cfg.Timeout))
		}

		n.log.Printf("Receiving packets from %s", remoteAddr.String())
	}

	var writeErrChan = make(chan error, 1)
	go func() {
		defer conn.Close()

		var writeErr error
		stdinBuf := make([]byte, 1024)
		for {
			nb, err := os.Stdin.Read(stdinBuf)
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
			if _, err := os.Stdout.Write(connBuff[:nb]); err != nil {
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

func setWriteBuffer(conn net.Conn, size int) error {
	if size > 0 {
		switch c := conn.(type) {
		case *net.UDPConn:
			return c.SetWriteBuffer(size)
		case *net.TCPConn:
			return c.SetWriteBuffer(size)
		case *net.UnixConn:
			return c.SetWriteBuffer(size)
		default:
			return fmt.Errorf("unsupported connection type for setting send buffer: %T", conn)
		}
	}
	return nil
}

func setReadBuffer(conn net.Conn, size int) error {
	if size > 0 {
		switch c := conn.(type) {
		case *net.UDPConn:
			return c.SetReadBuffer(size)
		case *net.TCPConn:
			return c.SetReadBuffer(size)
		case *net.UnixConn:
			return c.SetReadBuffer(size)
		default:
			return fmt.Errorf("unsupported connection type for setting receive buffer: %T", conn)
		}
	}

	return nil
}
