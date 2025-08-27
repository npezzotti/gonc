package main

import (
	"errors"
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

var (
	ErrInvalidIP   error = errors.New("invalid ip address")
	ErrInvalidPort error = errors.New("invalid port")
)

type Config struct {
	NetcatMode    NetcatMode
	Host          string
	Port          uint16
	Socket        Socket
	IPType        int
	NoStdin       bool
	Timeout       time.Duration
	NoDNS         bool
	ScanPorts     bool
	KeepListening bool
	ExitOnEOF     bool
	EndPort       uint16
	SourcePort    uint16
	SourceHost    string
	Verbose       bool
	Telnet        bool
	Interval      time.Duration
	UseSSL        bool
	SSLNoVerify   bool
	SSLCert       string
	SSLKey        string
	SSLTrustFile  string
	ServerName    string
	SSLCiphers    []uint16
	SSLAlpn       []string
	ProxyAddr     string
	ProxyType     ProxyType
	ProxyAuth     string
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

func (c *Config) Address() (string, error) {
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
					return "", fmt.Errorf("parse ip %s: %w", c.Host, err)
				}
			}

			return net.JoinHostPort(host, strconv.FormatUint(uint64(c.Port), 10)), nil
		default:
			return "", fmt.Errorf("invalid socket type: %s", c.Socket)
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
					return "", fmt.Errorf("parse ip %s: %w", c.Host, err)
				}
			} else {
				host = c.Host
			}
		default:
			return "", fmt.Errorf("invalid socket type: %s", c.Socket)
		}

		return net.JoinHostPort(host, strconv.FormatUint(uint64(c.Port), 10)), nil
	default:
		return "", fmt.Errorf("invalid mode: %s", c.NetcatMode)
	}
}

func parseIp(ip string) (string, error) {
	if ip == "" {
		return "", ErrInvalidIP
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", ErrInvalidIP
	}
	return parsedIP.String(), nil
}

// parsePortArg parses a port argument which can be a single port
// or a range for scanning (e.g., "80" or "80-90"). It returns the start and end ports.
// If no range is specified, the start and end ports will be the same.
func parsePortArg(arg string) (uint16, uint16, error) {
	ports := strings.SplitN(arg, "-", 2)
	port, err := strconv.ParseUint(ports[0], 10, 16)
	if err != nil {
		return 0, 0, ErrInvalidPort
	}

	start := uint16(port)
	end := start

	if len(ports) > 1 {
		endPort, err := strconv.ParseUint(ports[1], 10, 16)
		if err != nil {
			return 0, 0, ErrInvalidPort
		}
		end = uint16(endPort)
	}

	return start, end, nil
}
