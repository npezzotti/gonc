package main

import (
	"net"
	"time"
)

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
		if err := c.Conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

func (c *idleTimeoutConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		if err := c.Conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(b)
}
