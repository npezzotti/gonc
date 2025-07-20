package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"sync"
)

type HexFileOutput struct {
	filePath  string
	fileMutex sync.Mutex
}

func NewHexFileOutput(filePath string, appendOnly bool) (*HexFileOutput, error) {
	fileOpts := os.O_CREATE | os.O_WRONLY
	if appendOnly {
		fileOpts |= os.O_APPEND
	} else {
		fileOpts |= os.O_TRUNC
	}

	f, err := os.OpenFile(filePath, fileOpts, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close file: %w", err)
	}

	return &HexFileOutput{
		filePath: f.Name(),
	}, nil
}

func (o *HexFileOutput) Write(b []byte) (int, error) {
	if o != nil {
		o.fileMutex.Lock()
		defer o.fileMutex.Unlock()

		fileOpts := os.O_CREATE | os.O_WRONLY | os.O_APPEND
		f, err := os.OpenFile(o.filePath, fileOpts, 0o644)
		if err != nil {
			return 0, fmt.Errorf("open file: %w", err)
		}

		if _, err := f.Write([]byte(hex.Dump(b))); err != nil {
			return 0, err
		}

		if err := f.Close(); err != nil {
			return len(b), fmt.Errorf("close file: %w", err)
		}
	}

	return len(b), nil
}
