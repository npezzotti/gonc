package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
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

type idleTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func newIdleTimeoutConn(conn net.Conn, timeout time.Duration) *idleTimeoutConn {
	return &idleTimeoutConn{
		Conn:    conn,
		timeout: timeout,
	}
}

func (c *idleTimeoutConn) Read(b []byte) (int, error) {
	if c.timeout > 0 {
		c.Conn.SetDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Read(b)
}

func (c *idleTimeoutConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		c.Conn.SetDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Write(b)
}

func enableSocketDebug(conn net.Conn) error {
	f, err := getFile(conn)
	if err != nil {
		return fmt.Errorf("get file descriptor: %w", err)
	}
	defer f.Close()

	fd := int(f.Fd())
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_DEBUG, 1)
	if err != nil {
		return fmt.Errorf("set socket option: %w", err)
	}

	return nil
}

func getFile(conn net.Conn) (*os.File, error) {
	var file *os.File
	var err error

	switch c := conn.(type) {
	case *net.TCPConn:
		file, err = c.File()
	case *net.UDPConn:
		file, err = c.File()
	case *net.UnixConn:
		file, err = c.File()
	default:
		err = fmt.Errorf("unsupported connection type: %T", conn)
	}

	return file, err
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
