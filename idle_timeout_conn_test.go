package main

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func Test_newIdleTimeoutConn(t *testing.T) {
	mockConn := &mockNetConn{}
	timeout := time.Second * 2
	tc := newIdleTimeoutConn(mockConn, timeout)
	if tc.Conn != mockConn {
		t.Errorf("expected conn to be %v, got %v", mockConn, tc.Conn)
	}
	if tc.timeout != timeout {
		t.Errorf("expected timeout to be %v, got %v", timeout, tc.timeout)
	}
}

func Test_idleTimeoutConn_Read(t *testing.T) {
	readData := []byte("foobar")
	tc := idleTimeoutConn{
		Conn: &mockNetConn{
			reader: bytes.NewBuffer(readData),
		},
	}

	buf := make([]byte, 6)
	n, err := tc.Read(buf)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if n != 6 {
		t.Errorf("expected to read 6 bytes, got %d", n)
	}
	if !bytes.Equal(buf, readData) {
		t.Errorf("expected to read %q, got '%q'", readData, buf)
	}
}

func Test_idleTimeoutConn_Read_PropagatesError(t *testing.T) {
	mockConn := &mockNetConn{
		readErr: errors.New("read error"),
	}
	tc := idleTimeoutConn{
		Conn: mockConn,
	}

	buf := make([]byte, 5)
	n, err := tc.Read(buf)
	if err != mockConn.readErr {
		t.Errorf("expected error %v, got %v", mockConn.readErr, err)
	}
	if n != 0 {
		t.Errorf("expected to read 0 bytes, got %d", n)
	}
}

func Test_idleTimeoutConn_Write(t *testing.T) {
	mockConn := &mockNetConn{
		writer: &bytes.Buffer{},
	}
	tc := idleTimeoutConn{
		Conn: mockConn,
	}

	writeData := []byte("hello")
	n, err := tc.Write(writeData)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if n != 5 {
		t.Errorf("expected to write 5 bytes, got %d", n)
	}
	if !bytes.Equal(mockConn.writer.(*bytes.Buffer).Bytes(), writeData) {
		t.Errorf("expected to write 'hello', got %q", mockConn.writer.(*bytes.Buffer).String())
	}
}

func Test_idleTimeoutConn_Write_PropagatesError(t *testing.T) {
	mockConn := &mockNetConn{
		writer:   &bytes.Buffer{},
		writeErr: errors.New("write error"),
	}
	tc := idleTimeoutConn{
		Conn: mockConn,
	}

	n, err := tc.Write([]byte("hello"))
	if err != mockConn.writeErr {
		t.Errorf("expected error %v, got %v", mockConn.writeErr, err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes written, got %d", n)
	}
}

func Test_idleTimeoutConn_ReadWrite_ExtendsDeadline(t *testing.T) {
	tcases := []struct {
		name    string
		timeout time.Duration
	}{
		{name: "should extend deadline", timeout: time.Second * 2},
		{name: "should not extend deadline"},
	}

	for _, tt := range tcases {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockNetConn{
				reader:        bytes.NewBuffer([]byte("data")),
				writer:        &bytes.Buffer{},
				setDeadlineCh: make(chan time.Time, 1),
			}

			tc := idleTimeoutConn{
				Conn:    mockConn,
				timeout: tt.timeout,
			}

			if _, err := tc.Read(make([]byte, 10)); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			select {
			case <-mockConn.setDeadlineCh:
				if tt.timeout == 0 {
					t.Error("expected SetDeadline not to be called in Read")
				}
			default:
				if tt.timeout > 0 {
					t.Error("expected SetDeadline to be called in Read")
				}
			}

			if _, err := tc.Write([]byte("hello")); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			select {
			case <-mockConn.setDeadlineCh:
				if tt.timeout == 0 {
					t.Error("expected SetDeadline not to be called in Read")
				}
			default:
				if tt.timeout > 0 {
					t.Error("expected SetDeadline to be called in Read")
				}
			}
		})
	}

}
