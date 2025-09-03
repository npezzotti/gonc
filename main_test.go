package main

import (
	"bytes"
	"log"
	"testing"
)

func TestRun_VersionFlag(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := log.New(buf, "", 0)

	err := run(logger, []string{"-version"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("dev")) {
		t.Errorf("expected version output, got %s", buf.String())
	}
}
