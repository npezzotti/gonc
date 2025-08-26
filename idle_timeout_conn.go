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
