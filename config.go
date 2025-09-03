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
	NoShutdown    bool
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

func parseConfig(f *flags, args []string) (*Config, error) {
	cfg := NewDefaultConfig()

	if f.listen {
		cfg.NetcatMode = NetcatModeListen
	}

	cfg.Socket = parseSocketFlags(f.udp, f.useUnix)

	if f.ipv4_only {
		cfg.IPType = IPv4
	} else if f.ipv6_only {
		cfg.IPType = IPv6
	} else {
		cfg.IPType = IPv4v6
	}

	var err error
	cfg.Timeout, err = time.ParseDuration(f.timeout)
	if err != nil {
		return nil, fmt.Errorf("unable to parse connect timeout: %w", err)
	}

	switch cfg.NetcatMode {
	case NetcatModeConnect:
		switch cfg.Socket {
		case SocketTCP, SocketUDP:
			if len(args) < 2 {
				return nil, fmt.Errorf("host and port required")
			}

			cfg.Host = args[0]
			start, end, err := parsePortArg(args[1])
			if err != nil {
				return nil, fmt.Errorf("error parsing port: %w", err)
			}

			cfg.Port = start
			cfg.EndPort = end
		case SocketUnix, SocketUnixgram:
			if len(args) < 1 {
				return nil, fmt.Errorf("socket required")
			}

			cfg.Host = args[0]
		}
	case NetcatModeListen:
		switch cfg.Socket {
		case SocketTCP, SocketUDP:
			if len(args) == 1 {
				port, err := strconv.ParseUint(args[0], 10, 16)
				if err != nil {
					return nil, fmt.Errorf("couldn't parse port: %w", err)
				}

				cfg.Port = uint16(port)
			} else if len(args) >= 2 {
				cfg.Host = args[0]

				port, err := strconv.ParseUint(args[1], 10, 16)
				if err != nil {
					return nil, fmt.Errorf("couldn't parse port: %w", err)
				}

				cfg.Port = uint16(port)
			}
		case SocketUnix, SocketUnixgram:
			cfg.Host = args[0]
		}
	}

	// SSL options
	cfg.UseSSL = f.ssl
	cfg.SSLNoVerify = f.sslNoVerify
	cfg.SSLCert = f.sslCert
	cfg.SSLKey = f.sslKey
	cfg.SSLTrustFile = f.sslTrustFile

	// Proxy options
	cfg.ProxyType = ProxyType(f.proxyType)

	var addr = f.proxyAddr
	proxyAddrParts := strings.Split(addr, ":")
	if len(proxyAddrParts) < 2 && proxyAddrParts[0] != "" {
		switch cfg.ProxyType {
		case ProxyTypeHTTP:
			addr = fmt.Sprintf("%s:3218", proxyAddrParts[0])
		case ProxyTypeSOCKS5:
			addr = fmt.Sprintf("%s:1080", proxyAddrParts[0])
		}
	}

	cfg.ProxyAddr = addr
	cfg.ProxyAuth = f.proxyAuth

	alpn := strings.Split(f.sslAlpn, ",")
	alpnList := make([]string, 0, len(alpn))
	for _, proto := range alpn {
		proto = strings.TrimSpace(proto)
		if proto != "" {
			alpnList = append(alpnList, proto)
		}
	}
	if len(alpnList) > 0 {
		cfg.SSLAlpn = alpnList
	}

	cfg.ServerName = cfg.Host // Default to the host for server name verification
	if f.sslServerName != "" {
		cfg.ServerName = f.sslServerName
	}

	cfg.SSLCiphers, err = parseCipherSuite(f.sslCiphers)
	if err != nil {
		return nil, fmt.Errorf("invalid SSL ciphers: %w", err)
	}

	// Miscellaneous options
	cfg.SourcePort = uint16(f.sourcePort)
	cfg.SourceHost = f.sourceAddr
	cfg.NoDNS = f.noDNS
	cfg.NoStdin = f.nostdin
	cfg.ScanPorts = f.scan
	cfg.KeepListening = f.keepListening
	cfg.NoShutdown = f.noShutdown
	cfg.Verbose = f.verbose
	cfg.Telnet = f.telnet

	cfg.Interval, err = time.ParseDuration(f.interval)
	if err != nil {
		return nil, fmt.Errorf("unable to parse interval: %w", err)
	}

	return cfg, nil
}

func parseSocketFlags(udp, unix bool) Socket {
	if udp && unix {
		return SocketUnixgram
	} else if udp {
		return SocketUDP
	} else if unix {
		return SocketUnix
	}
	return SocketTCP
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

	fmt.Println("Parsed port:", port)
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
