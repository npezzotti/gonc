package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

func init() {
	log.SetFlags(0)
	log.SetPrefix("gonc: ")
}

var (
	// Basic flags
	listen        = flag.Bool("l", false, "listen for an incoming connection rather than initiate a connection to a remote host.")
	udp           = flag.Bool("u", false, "use UDP instead of the default option of TCP.")
	unix          = flag.Bool("U", false, "use Unix Domain Sockets")
	ipv4_only     = flag.Bool("4", false, "use IPv4 addresses only")
	ipv6_only     = flag.Bool("6", false, "use IPv6 addresses only")
	nostdin       = flag.Bool("d", false, "do not attempt to read from stdin")
	keepListening = flag.Bool("k", false, "  When a connection is completed, listen for another one.  Requires -l."+
		"When used together with the -u option, the server socket is not connected and it can receive UDP datagrams from multiple hosts.")
	exitOnEOF  = flag.Bool("N", false, "exit when EOF is received on stdin.  This is the default behavior, but can be disabled with this flag.")
	noDNS      = flag.Bool("n", false, "do not resolve hostnames to IP addresses")
	sourceAddr = flag.String("s", "", "the IP of the interface which is used to send the packets.")
	sourcePort = flag.Uint("p", 0, "the source port nc should use, subject to privilege restrictions and availability.")
	timeout    = flag.String("w", "0s", "connections which cannot be established or are idle timeout "+
		"after timeout seconds. Has no effect on the -listen option, i.e. nc will listen forever for a connection, "+
		"with or without the -w flag.")
	scan   = flag.Bool("z", false, "scan for listening daemons, without sending any data to them.")
	telnet = flag.Bool("t", false, "send RFC 854 DON'T and WON'T responses to RFC 854 DO and WILL requests. "+
		"This makes it possible to script telnet sessions.")
	verbose = flag.Bool("v", false, "enable more verbose output.")
	debug   = flag.Bool("D", false, "enable debugging on the socket. Only works for TCP connections.")

	// SSL
	ssl           = flag.Bool("ssl", false, "Connect or listen with SSL")
	sslCert       = flag.String("cert", "", "Specify SSL certificate file (PEM) for listening")
	sslKey        = flag.String("key", "", "Specify SSL private key (PEM) for listening")
	sslNoVerify   = flag.Bool("no-verify", false, "Do not verify trust and domain name of certificates")
	sslTrustFile  = flag.String("trustfile", "", "PEM file containing trusted SSL certificates")
	sslCiphers    = flag.String("ciphers", "", "Comma-separated list of SSL cipher suites")
	sslServerName = flag.String("servername", "", "Request distinct server name (SNI)")
	sslAlpn       = flag.String("alpn", "", "Comma-separated list of ALPN protocols to use")

	// Proxy
	proxyAddr = flag.String("proxy", "", "Specify address of host to proxy through.")
	proxyType = flag.String("proxy-type", "5", "Use proxy_protocol when talking to the proxy server. "+
		"Supported protocols are 5 (SOCKS v.5) and connect (HTTPS proxy). If the protocol is not specified, SOCKS version 5 is used.")
	proxyAuth = flag.String("proxy-auth", "", "Specify proxy authentication credentials (username:password).")
)

func generateConfig() (*Config, error) {
	cfg := NewDefaultConfig()

	if *listen {
		cfg.NetcatMode = NetcatModeListen
	}

	cfg.Socket = parseSocketFlags(*udp, *unix)
	cfg.Socket = parseSocketFlags(*udp, *unix)

	if *ipv4_only {
		cfg.IPType = IPv4
		cfg.IPType = IPv4
	} else if *ipv6_only {
		cfg.IPType = IPv6
		cfg.IPType = IPv6
	} else {
		cfg.IPType = IPv4v6
		cfg.IPType = IPv4v6
	}

	var err error
	cfg.Timeout, err = time.ParseDuration(*timeout)
	if err != nil {
		return nil, fmt.Errorf("unable to parse connect timeout: %w", err)
	}

	switch cfg.NetcatMode {
	case NetcatModeConnect:
		switch cfg.Socket {
		case SocketTCP, SocketUDP:
			if len(flag.Args()) < 2 {
				return nil, fmt.Errorf("host and port required")
			}

			cfg.Host = flag.Arg(0)
			start, end, err := parsePortArg(flag.Arg(1))
			if err != nil {
				return nil, fmt.Errorf("error parsing port: %w", err)
			}

			cfg.Port = start
			cfg.EndPort = end
		case SocketUnix, SocketUnixgram:
			if len(flag.Args()) < 1 {
				flag.Usage()
				return nil, fmt.Errorf("socket required")
			}

			cfg.Host = flag.Arg(0)
		}
	case NetcatModeListen:
		switch cfg.Socket {
		case SocketTCP, SocketUDP:
			if len(flag.Args()) == 1 {
				port, err := strconv.ParseUint(flag.Arg(0), 10, 16)
				if err != nil {
					return nil, fmt.Errorf("couldn't parse port: %w", err)
				}

				cfg.Port = uint16(port)
			} else if len(flag.Args()) >= 2 {
				cfg.Host = flag.Arg(0)

				port, err := strconv.ParseUint(flag.Arg(1), 10, 16)
				if err != nil {
					return nil, fmt.Errorf("couldn't parse port: %w", err)
				}

				cfg.Port = uint16(port)
			}
		case SocketUnix, SocketUnixgram:
			cfg.Host = flag.Arg(0)
		}
	}

	// SSL configuration
	cfg.UseSSL = *ssl
	cfg.SSLNoVerify = *sslNoVerify
	cfg.SSLCert = *sslCert
	cfg.SSLKey = *sslKey
	cfg.SSLTrustFile = *sslTrustFile

	// Proxy configuration
	cfg.ProxyType = ProxyType(*proxyType)

	var addr = *proxyAddr
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
	cfg.ProxyAuth = *proxyAuth

	alpn := strings.Split(*sslAlpn, ",")
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
	if *sslServerName != "" {
		cfg.ServerName = *sslServerName
	}

	cfg.SSLCiphers, err = parseCipherSuite(*sslCiphers)
	if err != nil {
		return nil, fmt.Errorf("invalid SSL ciphers: %w", err)
	}

	cfg.SourcePort = uint16(*sourcePort)
	cfg.SourceHost = *sourceAddr
	cfg.NoDNS = *noDNS
	cfg.NoStdin = *nostdin
	cfg.ScanPorts = *scan
	cfg.KeepListening = *keepListening
	cfg.ExitOnEOF = *exitOnEOF
	cfg.Verbose = *verbose
	cfg.Telnet = *telnet
	cfg.DebugSocket = *debug

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

func main() {
	if err := run(log.Default()); err != nil {
		log.Fatalln(err)
	}
}

func run(l *log.Logger) error {
	flag.Parse()
	cfg, err := generateConfig()
	if err != nil {
		return err
	}

	nc := &netcat{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		cfg:    cfg,
		log:    NewLogger(l, cfg),
	}

	network := cfg.Network()
	addr, err := cfg.ParseAddress()
	if err != nil {
		return err
	}

	if nc.cfg.NetcatMode == NetcatModeListen {
		return nc.runListen(network, addr)
	}

	return nc.runConnect(network, addr)
}
