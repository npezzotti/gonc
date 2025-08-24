package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type NetcatMode string

const (
	NetcatModeListen  NetcatMode = "listen"
	NetcatModeConnect NetcatMode = "connect"
)

type Socket string

func (s Socket) IsPacket() bool {
	return s == SocketUDP || s == SocketUnixgram
}

const (
	SocketTCP      Socket = "tcp"
	SocketUnix     Socket = "unix"
	SocketUDP      Socket = "udp"
	SocketUnixgram Socket = "unixgram"
)

const (
	IPv4 = iota
	IPv6
	IPv4v6
)

type Config struct {
	NetcatMode     NetcatMode
	Host           string
	Port           uint16
	Socket         Socket
	IPType         int
	NoStdin        bool
	Timeout        time.Duration
	NoDNS          bool
	ScanPorts      bool
	KeepListening  bool
	ExitOnEOF      bool
	EndPort        uint16
	SourcePort     uint16
	SourceHost     string
	Verbose        bool
	Telnet         bool
	DebugSocket    bool

	UseSSL       bool
	SSLNoVerify  bool
	SSLCert      string
	SSLKey       string
	SSLTrustFile string
	ServerName   string
	SSLCiphers   []uint16
	SSLAlpn      []string

	ProxyAddr string
	ProxyType ProxyType
	ProxyAuth string
}

var (
	DefaultIPv4Addr = "0.0.0.0"
	DefaultIPv6Addr = "::"
)

func NewDefaultConfig() *Config {
	return &Config{
		NetcatMode: NetcatModeConnect,
	}
}

func (c *Config) ParseAddress() (string, error) {
	switch c.NetcatMode {
	case NetcatModeListen:
		switch c.Socket {
		case SocketUnix, SocketUnixgram:
			return c.Host, nil
		case SocketTCP, SocketUDP:
			var host string
			var err error
			if c.Host == "" {
				switch c.IPType {
				case IPv6:
					host = DefaultIPv6Addr
				default:
					host = DefaultIPv4Addr
				}
			} else {
				host = c.Host
			}

			if c.NoDNS {
				host, err = parseIp(c.Host)
				if err != nil {
					return "", fmt.Errorf("couldn't parse ip: %w", err)
				}
			}

			return net.JoinHostPort(host, strconv.FormatUint(uint64(c.Port), 10)), nil
		default:
			return "", fmt.Errorf("couldn't parse address")
		}
	case NetcatModeConnect:
		var host string
		var err error
		if c.Host == "" {
			return "", fmt.Errorf("host is required")
		}

		switch c.Socket {
		case SocketUnix, SocketUnixgram:
			return c.Host, nil
		case SocketTCP, SocketUDP:
			if c.NoDNS {
				host, err = parseIp(c.Host)
				if err != nil {
					return "", err
				}
			} else {
				host = c.Host
			}
		}

		return net.JoinHostPort(host, strconv.FormatUint(uint64(c.Port), 10)), nil
	default:
		return "", fmt.Errorf("invalid netcat mode: %s", c.NetcatMode)
	}
}

func parseIp(ip string) (string, error) {
	if ip == "" {
		return "", fmt.Errorf("empty ip address")
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid ip address: %s", ip)
	}
	return parsedIP.String(), nil
}

func (c *Config) Network() string {
	switch c.Socket {
	case SocketTCP:
		switch c.IPType {
		case IPv4:
			return "tcp4"
		case IPv6:
			return "tcp6"
		default:
			return "tcp"
		}
	case SocketUDP:
		switch c.IPType {
		case IPv4:
			return "udp4"
		case IPv6:
			return "udp6"
		default:
			return "udp"
		}
	case SocketUnix:
		return "unix"
	case SocketUnixgram:
		return "unixgram"
	default:
		return ""
	}
}

// parsePortArg parses a port argument which can be a single port
// or a range for scanning (e.g., "80" or "80-90"). It returns the start and end ports.
// If no range is specified, the start and end ports will be the same.
func parsePortArg(arg string) (uint16, uint16, error) {
	ports := strings.SplitN(arg, "-", 2)
	port, err := strconv.ParseUint(ports[0], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("error parsing start port: %w", err)
	}

	start := uint16(port)
	end := start

	if len(ports) > 1 {
		endPort, err := strconv.ParseUint(ports[1], 10, 16)
		if err != nil {
			return 0, 0, fmt.Errorf("error parsing end port: %w", err)
		}
		end = uint16(endPort)
	}

	return start, end, nil
}
