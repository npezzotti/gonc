package main

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func Test_newTelnetConn(t *testing.T) {
	mockConn := &mockNetConn{}
	timeout := time.Second * 2
	tc := newTelnetConn(mockConn, timeout)
	if tc.Conn != mockConn {
		t.Errorf("expected conn to be %v, got %v", mockConn, tc.Conn)
	}
	if tc.timeout != timeout {
		t.Errorf("expected timeout to be %v, got %v", timeout, tc.timeout)
	}
}
func Test_processTelnet(t *testing.T) {
	tcases := []struct {
		name             string
		input            []byte
		expectedResponse []byte
		expectedData     []byte
	}{
		{
			name:             "commands with data",
			input:            []byte{IAC, WILL, ECHO, 'x', IAC, DO, ECHO, 'y', 'z'},
			expectedResponse: []byte{IAC, WONT, ECHO, IAC, DONT, ECHO},
			expectedData:     []byte{'x', 'y', 'z'},
		},
		{
			name:             "no commands",
			input:            []byte{'x', 'y', 'z'},
			expectedResponse: []byte{},
			expectedData:     []byte{'x', 'y', 'z'},
		},
		{
			name:             "multiple commands",
			input:            []byte{IAC, WILL, ECHO, IAC, DO, ECHO},
			expectedResponse: []byte{IAC, WONT, ECHO, IAC, DONT, ECHO},
			expectedData:     []byte{},
		},
	}

	for _, tt := range tcases {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockNetConn{writer: &bytes.Buffer{}}

			tc := &telnetConn{buffer: bytes.Buffer{}}
			tc.processTelnet(tt.input, mockConn)

			res := mockConn.writer.(*bytes.Buffer).Bytes()
			if !bytes.Equal(res, tt.expectedResponse) {
				t.Errorf("Expected responses %v, got %v", tt.expectedResponse, res)
			}

			if !bytes.Equal(tc.buffer.Bytes(), tt.expectedData) {
				t.Errorf("Expected buffered data %v, got %v", tt.expectedData, tc.buffer.Bytes())
			}
		})
	}
}

func Test_telnetConnRead_BufferHasData(t *testing.T) {
	tc := &telnetConn{buffer: bytes.Buffer{}}
	if _, err := tc.buffer.Write([]byte("abc")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	buf := make([]byte, 10)
	n, err := tc.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if n != 3 || string(buf[:n]) != "abc" {
		t.Errorf("expected \"abc\", got %q", buf[:n])
	}
}

func Test_telnetConnRead_ProcessesTelnetCommands(t *testing.T) {
	input := []byte{IAC, WILL, ECHO, 'x', IAC, DO, ECHO, 'y', 'z'}
	expectedResponse := []byte{IAC, WONT, ECHO, IAC, DONT, ECHO}
	expectedData := []byte{'x', 'y', 'z'}

	mockConn := &mockNetConn{
		reader: bytes.NewBuffer(input),
		writer: &bytes.Buffer{},
	}
	tc := &telnetConn{
		Conn:   mockConn,
		buffer: bytes.Buffer{},
	}
	buf := make([]byte, 10)
	n, err := tc.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(buf[:n], expectedData) {
		t.Errorf("expected \"abc\", got %q", buf[:n])
	}

	res := mockConn.writer.(*bytes.Buffer).Bytes()
	if !bytes.Equal(res, expectedResponse) {
		t.Errorf("expected response %v, got %v", expectedResponse, res)
	}
}

func TestTelnetConn_Read_PropagatesConnError(t *testing.T) {
	mockConn := &mockNetConn{
		reader:  &bytes.Buffer{},
		readErr: io.ErrUnexpectedEOF,
		writer:  &bytes.Buffer{},
	}
	tc := &telnetConn{
		Conn:   mockConn,
		buffer: bytes.Buffer{},
	}
	buf := make([]byte, 10)
	n, err := tc.Read(buf)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("expected error %v, got %v", io.ErrUnexpectedEOF, err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes read, got %d", n)
	}
}

func Test_telnetConn_Read_ExtendsDeadline(t *testing.T) {
	tcases := []struct {
		name    string
		timeout time.Duration
	}{
		{
			name:    "should extend deadline",
			timeout: time.Second * 2,
		},
		{
			name:    "should not extend deadline",
			timeout: 0,
		},
	}

	for _, tt := range tcases {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockNetConn{
				reader:        bytes.NewBuffer([]byte("data")),
				setDeadlineCh: make(chan time.Time, 1),
			}
			tc := telnetConn{
				Conn:    mockConn,
				timeout: tt.timeout,
				buffer:  bytes.Buffer{},
			}

			if _, err := tc.Read(make([]byte, 10)); err != nil {
				t.Fatalf("unexpected error: %v", err)
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

func Test_telnetConn_Write_ExtendsDeadline(t *testing.T) {
	tcases := []struct {
		name    string
		timeout time.Duration
	}{
		{
			name:    "should extend deadline",
			timeout: time.Second * 2,
		},
		{
			name:    "should not extend deadline",
			timeout: 0,
		},
	}

	for _, tt := range tcases {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockNetConn{
				writer:        &bytes.Buffer{},
				setDeadlineCh: make(chan time.Time, 1),
			}
			tc := telnetConn{
				Conn:    mockConn,
				timeout: tt.timeout,
				buffer:  bytes.Buffer{},
			}

			if _, err := tc.Write([]byte("test")); err != nil {
				t.Fatalf("unexpected error: %v", err)
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
