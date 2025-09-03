package main

import (
	"net"
	"os"
	"reflect"
	"testing"
)

func TestNewUDPListener(t *testing.T) {
	tcases := []struct {
		name, protocol, laddr string
		expectedType          net.Conn
		err                   string
	}{
		{
			name:         "udp",
			protocol:     "udp",
			laddr:        ":8080",
			expectedType: &net.UDPConn{},
		},
		{
			name:         "udp4",
			protocol:     "udp4",
			laddr:        ":8080",
			expectedType: &net.UDPConn{},
		},
		{
			name:         "udp6",
			protocol:     "udp6",
			laddr:        ":8080",
			expectedType: &net.UDPConn{},
		},
		{
			name:         "unixgram",
			protocol:     "unixgram",
			laddr:        "test.sock",
			expectedType: &net.UnixConn{},
		},
		{
			name:     "invalid protocol",
			protocol: "doesnotexist",
			err:      "unsupported protocol: doesnotexist",
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := NewUDPListener(tc.protocol, tc.laddr)
			t.Cleanup(func() {
				if ln != nil {
					ln.Close()
				}
				if tc.protocol == "unixgram" {
					// Remove the socket file after the test
					os.Remove(tc.laddr)
				}
			})

			if tc.err != "" {
				if err == nil || err.Error() != tc.err {
					t.Fatalf("expected error %q, got %q", tc.err, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if ln.conn == nil {
				t.Fatal("expected non-nil connection")
			}
			// Check if the connection is of the expected type
			if reflect.TypeOf(ln.conn) != reflect.TypeOf(tc.expectedType) {
				t.Fatalf("expected connection to be %T, got %T", tc.expectedType, ln.conn)
			}
		})
	}
}

func TestUDPListener_Accept(t *testing.T) {
	mockConn := &mockNetConn{}
	ln := UDPListener{conn: mockConn}

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if conn != mockConn {
		t.Fatalf("expected connection to be %v, got %v", mockConn, conn)
	}
}

func TestUDPListener_Close(t *testing.T) {
	ln := UDPListener{conn: &mockNetConn{}}

	ln.Close()
	if ln.conn.(*mockNetConn).closed != true {
		t.Fatal("expected connection to be closed")
	}
}

func TestUDPListener_Addr(t *testing.T) {
	conn := &mockNetConn{}
	ln := UDPListener{conn}

	if ln.Addr() != conn.addr {
		t.Fatal("expected Addr to return connection's local address")
	}
}
