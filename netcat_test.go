package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

func Test_netcat_handleConn(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *Config
		stdin      io.Reader
		stdout     io.Writer
		conn       *mockNetConn
		wantStdin  string
		wantStdout string
	}{
		{
			name:       "copy stdin to conn and conn to stdout",
			cfg:        &Config{},
			stdin:      bytes.NewBufferString("hello\n"),
			stdout:     &bytes.Buffer{},
			conn:       &mockNetConn{reader: bytes.NewBufferString("world\n"), writer: &bytes.Buffer{}},
			wantStdin:  "hello\n",
			wantStdout: "world\n",
		},
		{
			name:       "conn to stdout no stdin",
			cfg:        &Config{NoStdin: true},
			stdin:      nil,
			stdout:     &bytes.Buffer{},
			conn:       &mockNetConn{reader: bytes.NewBufferString("world\n"), writer: &bytes.Buffer{}},
			wantStdin:  "",
			wantStdout: "world\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nc := &netcat{
				cfg:    tt.cfg,
				stdin:  tt.stdin,
				stdout: tt.stdout,
			}
			err := nc.handleConn(tt.conn)
			if err != nil {
				t.Fatalf("handleConn error: %v", err)
			}
			if tt.stdin != nil {
				if got := tt.conn.writer.(*bytes.Buffer).String(); got != tt.wantStdin {
					t.Errorf("wrote %q to conn, expected %q", got, tt.wantStdin)
				}
			}
			if got := tt.stdout.(*bytes.Buffer).String(); got != tt.wantStdout {
				t.Errorf("wrote %q to stdout, expected %q", got, tt.wantStdout)
			}
		})
	}
}

func Test_scanLinesWithInterval(t *testing.T) {
	src, dst := bytes.Buffer{}, bytes.Buffer{}
	data := []byte("line 1\nline 2\nline 3\n")
	src.Write(data)

	start := time.Now()
	dur := time.Millisecond * 100
	if err := scanLinesWithInterval(&dst, &src, dur); err != nil {
		t.Fatalf("failed to scan lines: %v", err)
	}
	if !bytes.Equal(dst.Bytes(), data) {
		t.Errorf("unexpected output: %q", dst.String())
	}
	since := time.Since(start)
	if since < dur {
		t.Errorf("expected at least %v delay, got %v", dur, since)
	}
}

func Test_closeWrite(t *testing.T) {
	m := &mockNetConn{}
	if err := closeWrite(m); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	if !m.closed {
		t.Errorf("expected CloseWrite to be called")
	}
}

func Test_closeWrite_ErrorFromCloseWrite(t *testing.T) {
	m := &mockNetConn{closeErr: errors.New("close error")}
	err := closeWrite(m)
	if err == nil || err.Error() != "close error" {
		t.Errorf("expected 'close error', got %v", err)
	}
	if m.closed {
		t.Errorf("expected CloseWrite ")
	}
}

func Test_netcat_copyPackets_connect(t *testing.T) {
	stdinData := []byte("test stdin data")
	stdoutBuf := &bytes.Buffer{}
	n := &netcat{
		stdin:  bytes.NewBuffer(stdinData),
		stdout: stdoutBuf,
		cfg: &Config{
			NetcatMode: NetcatModeConnect,
		},
	}

	connData := []byte("test conn data")
	connWriterBuff := &bytes.Buffer{}
	mockConn := &mockNetConn{
		reader: bytes.NewBuffer(connData),
		writer: connWriterBuff,
	}

	err := n.copyPackets(mockConn)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !bytes.Equal(connWriterBuff.Bytes(), stdinData) {
		t.Errorf("unexpected output: %q", connWriterBuff.Bytes())
	}
	if !bytes.Equal(stdoutBuf.Bytes(), connData) {
		t.Errorf("unexpected output: %q", stdoutBuf.Bytes())
	}
}

func Test_netcat_copyPackets_listen_mode(t *testing.T) {
	stdinData := []byte("test stdin data")
	stdoutBuf := &bytes.Buffer{}
	logBuf := &bytes.Buffer{}
	n := &netcat{
		stdin:  bytes.NewBuffer(stdinData),
		stdout: stdoutBuf,
		cfg: &Config{
			NetcatMode: NetcatModeListen,
		},
		log: NewLogger(log.New(logBuf, "", 0), &Config{Verbose: true}),
	}

	connData := []byte("test conn data")
	connWriterBuf := &bytes.Buffer{}
	mockConn := &mockNetConn{
		reader: bytes.NewReader(connData),
		writer: connWriterBuf,
		addr:   &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 0},
	}

	err := n.copyPackets(mockConn)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !bytes.Equal(connWriterBuf.Bytes(), stdinData) {
		t.Errorf("expected connWriterBuf to contain stdinData, got %q", connWriterBuf.Bytes())
	}
	if !bytes.Equal(stdoutBuf.Bytes(), connData) {
		t.Errorf("expected stdoutBuf to contain connData, got %q", stdoutBuf.Bytes())
	}
	if !bytes.Contains(logBuf.Bytes(), fmt.Appendf(nil, "Receiving packets from %s", mockConn.addr.String())) {
		t.Errorf("unexpected log output: %q", logBuf.String())
	}
}
