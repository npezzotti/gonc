package main

import (
	"crypto/tls"
	"slices"
	"testing"
)

func Test_parseCipherSuite(t *testing.T) {
	tcases := []struct {
		name, input string
		expected    []uint16
		err         error
	}{
		{
			name:  "single valid cipher",
			input: "TLS_AES_128_GCM_SHA256",
			expected: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
			},
			err: nil,
		},
		{
			name:  "multiple valid ciphers",
			input: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
			expected: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
			},
			err: nil,
		},
		{
			name:     "empty cipher string",
			input:    "",
			expected: nil,
			err:      nil,
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCipherSuite(tc.input)
			if err != nil {
				if tc.err == nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if err.Error() != tc.err.Error() {
					t.Fatalf("expected error: %v, got: %v", tc.err, err)
				}
				return
			}

			if !slices.Equal(got, tc.expected) {
				t.Fatalf("expected: %v, got: %v", tc.expected, got)
			}
		})
	}
}
