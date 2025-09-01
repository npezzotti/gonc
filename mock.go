package main

import (
	"io"
	"net"
	"time"
)

type mockListener struct {
	addr net.Addr
}

func (m *mockListener) Accept() (net.Conn, error) {
	return &mockNetConn{
		setDeadlineCh: make(chan time.Time, 1),
	}, nil
}

func (m *mockListener) Close() error {
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return m.addr
}

// mockNetConn is a mock implementation of the net.Conn and net.PacketConn interfaces for testing.
type mockNetConn struct {
	reader        io.Reader
	writer        io.Writer
	addr          net.Addr
	readErr       error
	writeErr      error
	setDeadlineCh chan time.Time
	closed        bool
}

func (m *mockNetConn) Write(b []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return m.writer.Write(b)
}

func (m *mockNetConn) Read(b []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	return m.reader.Read(b)
}

func (m *mockNetConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockNetConn) CloseWrite() error {
	return nil
}

func (m *mockNetConn) LocalAddr() net.Addr  { return m.addr }
func (m *mockNetConn) RemoteAddr() net.Addr { return m.addr }

func (m *mockNetConn) SetDeadline(t time.Time) error {
	if m.setDeadlineCh != nil {
		m.setDeadlineCh <- t
	}
	return nil
}
func (m *mockNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockNetConn) SetWriteDeadline(t time.Time) error { return nil }

func (m *mockNetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if m.readErr != nil {
		err = m.readErr
		return
	}
	n, err = m.reader.Read(p)
	addr = m.addr
	return
}

func (m *mockNetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return m.writer.Write(p)
}
