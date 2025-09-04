package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.NetcatMode != NetcatModeConnect {
		t.Fatal("expected NetcatModeConnect")
	}
}

func TestConfigNetwork(t *testing.T) {
	tcases := []struct {
		cfg      *Config
		expected string
	}{
		{cfg: &Config{Socket: SocketTCP, IPType: IPv4}, expected: "tcp4"},
		{cfg: &Config{Socket: SocketTCP, IPType: IPv6}, expected: "tcp6"},
		{cfg: &Config{Socket: SocketTCP, IPType: IPv4v6}, expected: "tcp"},
		{cfg: &Config{Socket: SocketUDP, IPType: IPv4}, expected: "udp4"},
		{cfg: &Config{Socket: SocketUDP, IPType: IPv6}, expected: "udp6"},
		{cfg: &Config{Socket: SocketUDP, IPType: IPv4v6}, expected: "udp"},
		{cfg: &Config{Socket: SocketUnix}, expected: "unix"},
		{cfg: &Config{Socket: SocketUnixgram}, expected: "unixgram"},
		{cfg: &Config{Socket: SocketUnixgram}, expected: "unixgram"},
		{cfg: &Config{}, expected: ""},
	}

	for _, tc := range tcases {
		if network := tc.cfg.Network(); network != tc.expected {
			t.Errorf("expected %s, got %s", tc.expected, network)
		}
	}
}

func TestConfigAddress(t *testing.T) {
	tcases := []struct {
		name     string
		cfg      *Config
		expected string
		errStr   string
	}{
		{
			name: "listen unix",
			cfg: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     SocketUnix,
				Host:       "test.sock",
				NoDNS:      true,
			},
			expected: "test.sock",
		},
		{
			name: "listen unixgram",
			cfg: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     SocketUnixgram,
				Host:       "test.sock",
				NoDNS:      true,
			},
			expected: "test.sock",
		},
		{
			name: "listen tcp host and port",
			cfg: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     SocketTCP,
				Host:       "localhost",
				Port:       8080,
			},
			expected: "localhost:8080",
		},
		{
			name: "listen udp host and port",
			cfg: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     SocketUDP,
				Host:       "localhost",
				Port:       8080,
			},
			expected: "localhost:8080",
		},
		{
			name: "listen tcp no dns valid ip",
			cfg: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     SocketTCP,
				Host:       "192.168.1.4",
				Port:       8080,
				NoDNS:      true,
			},
			expected: "192.168.1.4:8080",
		},
		{
			name: "listen udp no dns valid ip",
			cfg: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     SocketUDP,
				Host:       "192.168.1.4",
				Port:       8080,
				NoDNS:      true,
			},
			expected: "192.168.1.4:8080",
		},
		{
			name: "listen tcp no dns invalid ip",
			cfg: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     SocketTCP,
				Host:       "localhost",
				Port:       8080,
				NoDNS:      true,
			},
			errStr: "parse ip localhost",
		},
		{
			name: "listen udp no dns invalid ip",
			cfg: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     SocketUDP,
				Host:       "localhost",
				Port:       8080,
				NoDNS:      true,
			},
			errStr: "parse ip localhost",
		},
		{
			name: "listen invalid socket",
			cfg: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     "invalid",
			},
			errStr: "invalid socket type",
		},
		{
			name: "connect no host",
			cfg: &Config{
				NetcatMode: NetcatModeConnect,
				Host:       "",
			},
			errStr: "host is required",
		},
		{
			name: "connect unix",
			cfg: &Config{
				NetcatMode: NetcatModeConnect,
				Socket:     SocketUnix,
				Host:       "test.sock",
				NoDNS:      true,
			},
			expected: "test.sock",
		},
		{
			name: "connect unixgram",
			cfg: &Config{
				NetcatMode: NetcatModeConnect,
				Socket:     SocketUnixgram,
				Host:       "test.sock",
				NoDNS:      true,
			},
			expected: "test.sock",
		},
		{
			name: "connect tcp host and port",
			cfg: &Config{
				NetcatMode: NetcatModeConnect,
				Socket:     SocketTCP,
				Host:       "localhost",
				Port:       8080,
			},
			expected: "localhost:8080",
		},
		{
			name: "connect udp host and port",
			cfg: &Config{
				NetcatMode: NetcatModeConnect,
				Socket:     SocketUDP,
				Host:       "localhost",
				Port:       8080,
			},
			expected: "localhost:8080",
		},
		{
			name: "connect tcp no dns valid ip",
			cfg: &Config{
				NetcatMode: NetcatModeConnect,
				Socket:     SocketTCP,
				Host:       "192.168.1.4",
				Port:       8080,
				NoDNS:      true,
			},
			expected: "192.168.1.4:8080",
		},
		{
			name: "connect udp no dns valid ip",
			cfg: &Config{
				NetcatMode: NetcatModeConnect,
				Socket:     SocketUDP,
				Host:       "192.168.1.4",
				Port:       8080,
				NoDNS:      true,
			},
			expected: "192.168.1.4:8080",
		},
		{
			name: "connect tcp no dns invalid ip",
			cfg: &Config{
				NetcatMode: NetcatModeConnect,
				Socket:     SocketTCP,
				Host:       "localhost",
				Port:       8080,
				NoDNS:      true,
			},
			errStr: "parse ip localhost",
		},
		{
			name: "connect udp no dns invalid ip",
			cfg: &Config{
				NetcatMode: NetcatModeConnect,
				Socket:     SocketUDP,
				Host:       "localhost",
				Port:       8080,
				NoDNS:      true,
			},
			errStr: "parse ip localhost",
		},
		{
			name: "invalid netcat mode",
			cfg: &Config{
				NetcatMode: "invalid",
			},
			errStr: "invalid mode",
		},
		{
			name: "connect invalid socket",
			cfg: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     "invalid",
			},
			errStr: "invalid socket type",
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := tc.cfg.Address()
			if err != nil && tc.errStr == "" {
				t.Fatalf("unexpected error: %v", err)
			}

			if err == nil && tc.errStr != "" {
				t.Errorf("expected %s, got nil", tc.errStr)
				return
			}

			if err != nil && !strings.Contains(err.Error(), tc.errStr) {
				t.Errorf("expected %s, got %v", tc.errStr, err)
				return
			}

			if addr != tc.expected {
				t.Fatal("expected address to be localhost:8080")
			}
		})
	}
}

func Test_parseConfig(t *testing.T) {
	tcases := []struct {
		name     string
		flags    *flags
		args     []string
		expected *Config
		errStr   string
	}{
		{
			name:  "default connect config",
			flags: &flags{},
			args:  []string{"localhost", "8080"},
			expected: &Config{
				NetcatMode: NetcatModeConnect,
				Socket:     SocketTCP,
				Host:       "localhost",
				Port:       8080,
			},
		},
		{
			name:   "connect no port",
			flags:  &flags{},
			args:   []string{"localhost"},
			errStr: "host and port required",
		},
		{
			name: "connect socket",
			flags: &flags{
				useUnix: true,
			},
			args: []string{"gonc_test.sock"},
			expected: &Config{
				NetcatMode: NetcatModeConnect,
				Socket:     SocketUnix,
				Host:       "gonc_test.sock",
			},
		},
		{
			name: "connect socket fails with no socket",
			flags: &flags{
				useUnix: true,
			},
			args:   []string{},
			errStr: "socket required",
		},
		{
			name: "listen host and port",
			flags: &flags{
				listen: true,
			},
			args: []string{"localhost", "8080"},
			expected: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     SocketTCP,
				Host:       "localhost",
				Port:       8080,
			},
		},
		{
			name: "listen no host",
			flags: &flags{
				listen: true,
			},
			args: []string{"8080"},
			expected: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     SocketTCP,
				Port:       8080,
			},
		},
		{
			name: "listen config fails with no port",
			flags: &flags{
				listen: true,
			},
			args:   []string{},
			errStr: "port required",
		},
		{
			name: "connect socket",
			flags: &flags{
				useUnix: true,
			},
			args: []string{"gonc_test.sock"},
			expected: &Config{
				NetcatMode: NetcatModeConnect,
				Socket:     SocketUnix,
				Host:       "gonc_test.sock",
			},
		},
		{
			name: "listen socket",
			flags: &flags{
				listen:  true,
				useUnix: true,
			},
			args: []string{"gonc_test.sock"},
			expected: &Config{
				NetcatMode: NetcatModeListen,
				Socket:     SocketUnix,
				Host:       "gonc_test.sock",
			},
		},
		{
			name: "ipv4",
			flags: &flags{
				ipv4_only: true,
			},
			args:     []string{"localhost", "8080"},
			expected: &Config{IPType: IPv4},
		},
		{
			name: "ipv6",
			flags: &flags{
				ipv6_only: true,
			},
			args:     []string{"localhost", "8080"},
			expected: &Config{IPType: IPv6},
		},
		{
			name:     "default ip type",
			flags:    &flags{},
			args:     []string{"localhost", "8080"},
			expected: &Config{IPType: IPv4v6},
		},
		{
			name: "successfully parses interval and timeout",
			flags: &flags{
				timeout:  "5s",
				interval: "1m",
			},
			args:     []string{"localhost", "8080"},
			expected: &Config{Timeout: 5 * time.Second, Interval: 1 * time.Minute},
		},
		{
			name: "fails to parse timeout",
			flags: &flags{
				timeout: "invalid",
			},
			args:   []string{"localhost", "8080"},
			errStr: "unable to parse connect timeout",
		},
		{
			name: "fails to parse interval",
			flags: &flags{
				interval: "invalid",
			},
			args:   []string{"localhost", "8080"},
			errStr: "unable to parse interval",
		},
		{
			name: "default proxy port http",
			flags: &flags{
				proxyType: "connect",
				proxyAddr: "localhost",
			},
			args: []string{"localhost", "8080"},
			expected: &Config{
				ProxyType: ProxyTypeHTTP,
				ProxyAddr: "localhost:3218",
			},
		},
		{
			name: "default proxy port socks5",
			flags: &flags{
				proxyType: "5",
				proxyAddr: "localhost",
			},
			args: []string{"localhost", "8080"},
			expected: &Config{
				ProxyType: ProxyTypeSOCKS5,
				ProxyAddr: "localhost:1080",
			},
		},
		{
			name: "default proxy port socks5",
			flags: &flags{
				proxyType: "5",
				proxyAddr: "localhost",
			},
			args: []string{"localhost", "8080"},
			expected: &Config{
				ProxyType: ProxyTypeSOCKS5,
				ProxyAddr: "localhost:1080",
			},
		},
		{
			name:   "fails to parse ciphers",
			flags:  &flags{sslCiphers: "invalid"},
			args:   []string{"localhost", "8080"},
			errStr: "invalid SSL ciphers",
		},
		{
			name:     "parses alpn",
			flags:    &flags{sslAlpn: "h2,http/1.1"},
			args:     []string{"localhost", "8080"},
			expected: &Config{SSLAlpn: []string{"h2", "http/1.1"}},
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseConfig(tc.flags, tc.args)
			if err != nil {
				if tc.errStr != "" {
					if !strings.Contains(err.Error(), tc.errStr) {
						t.Errorf("expected %q, got %q", tc.errStr, err.Error())
					}
					return
				} else {
					t.Errorf("unexpected error: %v", err)
				}
			}
			if tc.expected.NetcatMode != "" && result.NetcatMode != tc.expected.NetcatMode {
				t.Errorf("expected %v, got %v", tc.expected.NetcatMode, result.NetcatMode)
			}
			if tc.expected.Socket != "" && result.Socket != tc.expected.Socket {
				t.Errorf("expected %v, got %v", tc.expected.Socket, result.Socket)
			}
			if tc.expected.Host != "" && result.Host != tc.expected.Host {
				t.Errorf("expected %v, got %v", tc.expected.Host, result.Host)
			}
			if tc.expected.Port != 0 && result.Port != tc.expected.Port {
				t.Errorf("expected %v, got %v", tc.expected.Port, result.Port)
			}
			if tc.expected.EndPort != 0 && result.EndPort != tc.expected.EndPort {
				t.Errorf("expected %v, got %v", tc.expected.EndPort, result.EndPort)
			}
			if tc.expected.Timeout != 0 && result.Timeout != tc.expected.Timeout {
				t.Errorf("expected %v, got %v", tc.expected.Timeout, result.Timeout)
			}
			if tc.expected.Interval != 0 && result.Interval != tc.expected.Interval {
				t.Errorf("expected %v, got %v", tc.expected.Interval, result.Interval)
			}
			if result.NoStdin != tc.expected.NoStdin {
				t.Errorf("expected %v, got %v", tc.expected.NoStdin, result.NoStdin)
			}
			if result.NoDNS != tc.expected.NoDNS {
				t.Errorf("expected %v, got %v", tc.expected.NoDNS, result.NoDNS)
			}
			if result.ScanPorts != tc.expected.ScanPorts {
				t.Errorf("expected %v, got %v", tc.expected.ScanPorts, result.ScanPorts)
			}
			if result.KeepListening != tc.expected.KeepListening {
				t.Errorf("expected %v, got %v", tc.expected.KeepListening, result.KeepListening)
			}
			if result.NoShutdown != tc.expected.NoShutdown {
				t.Errorf("expected %v, got %v", tc.expected.NoShutdown, result.NoShutdown)
			}
			if result.Verbose != tc.expected.Verbose {
				t.Errorf("expected %v, got %v", tc.expected.Verbose, result.Verbose)
			}
			if result.Telnet != tc.expected.Telnet {
				t.Errorf("expected %v, got %v", tc.expected.Telnet, result.Telnet)
			}
			if tc.expected.ProxyAddr != "" && result.ProxyAddr != tc.expected.ProxyAddr {
				t.Errorf("expected %v, got %v", tc.expected.ProxyAddr, result.ProxyAddr)
			}
			if tc.expected.ProxyType != "" && result.ProxyType != tc.expected.ProxyType {
				t.Errorf("expected %v, got %v", tc.expected.ProxyType, result.ProxyType)
			}
			if tc.expected.ProxyAuth != "" && result.ProxyAuth != tc.expected.ProxyAuth {
				t.Errorf("expected %v, got %v", tc.expected.ProxyAuth, result.ProxyAuth)
			}
		})
	}
}

func Test_parseSocketFlags(t *testing.T) {
	tcases := []struct {
		name     string
		udp      bool
		unix     bool
		expected Socket
	}{
		{
			name:     "tcp by default",
			expected: SocketTCP,
		},
		{
			name:     "udp flag set",
			udp:      true,
			expected: SocketUDP,
		},
		{
			name:     "unix flag set",
			unix:     true,
			expected: SocketUnix,
		},
		{
			name:     "udp and unix flags set",
			udp:      true,
			unix:     true,
			expected: SocketUnixgram,
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseSocketFlags(tc.udp, tc.unix)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func Test_parseIp(t *testing.T) {
	tcases := []struct {
		name     string
		input    string
		expected string
		err      error
	}{
		{
			name:     "valid ipv4",
			input:    "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "valid ipv6",
			input:    "2001:db8::1",
			expected: "2001:db8::1",
		},
		{
			name:  "empty string",
			input: "",
			err:   ErrInvalidIP,
		},
		{
			name:  "hostname",
			input: "example.com",
			err:   ErrInvalidIP,
		},
	}

	for _, tt := range tcases {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseIp(tt.input)
			if err != nil && tt.err == nil {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && tt.err != nil {
				t.Errorf("expected error, got nil")
				return
			}
			if err != nil && !errors.Is(err, tt.err) {
				t.Errorf("expected %v, got %v", tt.err, err)
				return
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsPacket(t *testing.T) {
	tcases := []struct {
		socket Socket
		res    bool
	}{
		{socket: SocketUDP, res: true},
		{socket: SocketUnixgram, res: true},
		{socket: SocketTCP, res: false},
		{socket: SocketUnix, res: false},
	}

	for _, tc := range tcases {
		if tc.socket.IsPacket() != tc.res {
			t.Fatalf("expected IsPacket to return %t for %s", tc.res, tc.socket)
		}
	}
}

func Test_parsePortArg(t *testing.T) {
	tcases := []struct {
		name       string
		input      string
		start, end uint16
		err        error
	}{
		{
			name:  "parses single port",
			input: "80",
			start: 80,
			end:   80,
		},
		{
			name:  "parses port range",
			input: "80-90",
			start: 80,
			end:   90,
		},
		{
			name:  "fails to parse start port",
			input: "eighty-90",
			start: 0,
			end:   0,
			err:   ErrInvalidPort,
		},
		{
			name:  "fails to parse end port",
			input: "80-ninety",
			start: 0,
			end:   0,
			err:   ErrInvalidPort,
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, err := parsePortArg(tc.input)
			if err != nil && tc.err == nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err == nil && tc.err != nil {
				t.Errorf("expected %v, got nil", tc.err)
				return
			}
			if err != nil && tc.err != nil && !errors.Is(err, tc.err) {
				t.Errorf("expected error: %v, got: %v", tc.err, err)
				return
			}

			if start != tc.start || end != tc.end {
				t.Errorf("expected (%d, %d), got (%d, %d)", tc.start, tc.end, start, end)
			}
		})
	}
}
