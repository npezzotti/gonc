package main

import (
	"bytes"
	"log"
	"testing"
)

func TestLoggerVerbose(t *testing.T) {
	buf := &bytes.Buffer{}
	l := log.New(buf, "", 0)
	cfg := &Config{Verbose: true}
	logger := NewLogger(l, cfg)

	logger.Verbose("This is a verbose message: %s", "test")

	if buf.Len() == 0 {
		t.Error("Expected verbose log output, but got none")
	}
	if buf.String() != "This is a verbose message: test\n" {
		t.Errorf("Expected 'This is a verbose message: test\\n', got '%s'", buf.String())
	}
}

func TestLoggerLog(t *testing.T) {
	buf := &bytes.Buffer{}
	l := log.New(buf, "", 0)
	cfg := &Config{Verbose: true}
	logger := NewLogger(l, cfg)

	logger.Verbose("This is a regular message: %s", "test")

	if buf.Len() == 0 {
		t.Error("Expected log output, but got none")
	}
	if buf.String() != "This is a regular message: test\n" {
		t.Errorf("Expected 'This is a regular message: test\\n', got '%s'", buf.String())
	}
}
