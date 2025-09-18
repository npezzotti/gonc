package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Telnet command constants
const (
	WILL = 0xfb // WILL
	WONT = 0xfc // WON'T
	DO   = 0xfd // DO
	DONT = 0xfe // DON'T
	IAC  = 0xff // Interpret As Command
	ECHO = 0x01 // ECHO
)

type telnetConn struct {
	net.Conn
	timeout time.Duration
	buffer  bytes.Buffer
}

func newTelnetConn(conn net.Conn, timeout time.Duration) *telnetConn {
	return &telnetConn{
		Conn:    conn,
		timeout: timeout,
	}
}

func (c *telnetConn) Read(b []byte) (int, error) {
	// If there's data in the buffer, read from it first
	if c.buffer.Len() > 0 {
		return c.buffer.Read(b)
	}

	// Extend the deadline if timeout is set
	if c.timeout > 0 {
		if err := c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
			return 0, err
		}
	}

	// Read data into a temporary buffer to process telnet commands
	tmp := make([]byte, 2048)
	total, connErr := c.Conn.Read(tmp)

	if total > 0 {
		c.processTelnet(tmp[:total], c)
	}

	// Read remaining data from the buffer
	n, err := c.buffer.Read(b)
	if err != nil && !errors.Is(err, io.EOF) {
		// Only return EOF if received on the underlying connection
		return n, err
	}

	return n, connErr
}

func (c *telnetConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		if err := c.Conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
			return 0, fmt.Errorf("set deadline: %w", err)
		}
	}
	return c.Conn.Write(b)
}

// processTelnet processes telnet commands in the given data.
// It responds to DO and WILL commands with WONT and DONT respectively,
// and stores regular data in the buffer.
func (c *telnetConn) processTelnet(data []byte, conn net.Conn) {
	var i int
	for i < len(data) {
		if data[i] == IAC {
			command := data[i+1]
			option := data[i+2]

			switch command {
			case DO:
				// respond with WON'T for any DO request
				if _, err := conn.Write([]byte{IAC, DONT, option}); err != nil {
					continue
				}
			case WILL:
				// respond with DON'T for any WILL request
				if _, err := conn.Write([]byte{IAC, WONT, option}); err != nil {
					continue
				}
			}

			i += 3
		} else {
			c.buffer.WriteByte(data[i])
			i++
		}
	}
}
