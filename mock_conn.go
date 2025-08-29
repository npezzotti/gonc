package main

import (
	"bytes"
	"net"
	"time"
)

// mockNetConn is a mock implementation of net.Conn for testing purposes.
type mockNetConn struct {
	addr              net.Addr
	readData          []byte
	readErr           error
	writeBuf          *bytes.Buffer
	writeErr          error
	setDeadlineCalled bool
	closeCalled       bool
	localAddrCalled   bool
}

func (m *mockNetConn) Write(b []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return m.writeBuf.Write(b)
}

func (m *mockNetConn) Read(b []byte) (int, error) {
	n := copy(b, m.readData)
	m.readData = m.readData[n:]
	return n, m.readErr
}

func (m *mockNetConn) Close() error                       { m.closeCalled = true; return nil }
func (m *mockNetConn) LocalAddr() net.Addr                { m.localAddrCalled = true; return nil }
func (m *mockNetConn) RemoteAddr() net.Addr               { return m.addr }
func (m *mockNetConn) SetDeadline(t time.Time) error      { m.setDeadlineCalled = true; return nil }
func (m *mockNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockNetConn) SetWriteDeadline(t time.Time) error { return nil }
