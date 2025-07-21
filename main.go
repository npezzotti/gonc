package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

var (
	listen        = flag.Bool("l", false, "listen for an incoming connection rather than initiate a connection to a remote host.")
	udp           = flag.Bool("u", false, "use UDP instead of the default option of TCP.")
	unix          = flag.Bool("U", false, "use Unix Domain Sockets")
	nostdin       = flag.Bool("d", false, "do not attempt to read from stdin")
	ipv4_only     = flag.Bool("4", false, "use IPv4 addresses only")
	ipv6_only     = flag.Bool("6", false, "use IPv6 addresses only")
	keepListening = flag.Bool("k", false, "  When a connection is completed, listen for another one.  Requires -l."+
		"When used together with the -u option, the server socket is not connected and it can receive UDP datagrams from multiple hosts.")
	exitOnEOF  = flag.Bool("N", false, "exit when EOF is received on stdin.  This is the default behavior, but can be disabled with this flag.")
	nodns      = flag.Bool("n", false, "do not resolve hostnames to IP addresses")
	sourceAddr = flag.String("s", "", "the IP of the interface which is used to send the packets.")
	sourcePort = flag.Uint("p", 0, "the source port nc should use, subject to privilege restrictions and availability.")
	timeout    = flag.String("w", "0s", "connections which cannot be established or are idle timeout "+
		"after timeout seconds. Has no effect on the -listen option, i.e. nc will listen forever for a connection, "+
		"with or without the -w flag.")
	hexDumpFile = flag.String("hex-dump", "", "output file")
	append      = flag.Bool("append-output", false, "append to output file")
	scan        = flag.Bool("z", false, "scan for listening daemons, without sending any data to them.")
	recvBuf     = flag.Int("I", 0, "Specify the size of the TCP receive buffer.")
	sendBuf     = flag.Int("O", 0, "specify the size of the TCP send buffer.")
	verbose     = flag.Bool("v", false, "enable more verbose output.")
)

func generateConfig() (*Config, error) {
	cfg := NewDefaultConfig()

	if *listen {
		cfg.NetcatMode = NetcatModeListen
	}

	cfg.ProtocolConfig.Socket = parseSocketFlags(*udp, *unix)

	if *ipv4_only {
		cfg.ProtocolConfig.IPType = IPv4
	} else if *ipv6_only {
		cfg.ProtocolConfig.IPType = IPv6
	} else {
		cfg.ProtocolConfig.IPType = IPv4v6
	}

	timeout, err := time.ParseDuration(*timeout)
	if err != nil {
		return nil, fmt.Errorf("unable to parse connect timeout: %w", err)
	}

	cfg.ConnTimeout = timeout
	cfg.Timeout = timeout

	switch cfg.NetcatMode {
	case NetcatModeConnect:
		switch cfg.ProtocolConfig.Socket {
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
			cfg.StartPort = start
			cfg.EndPort = end
		case SocketUnix, SocketUnixgram:
			if len(flag.Args()) < 1 {
				flag.Usage()
				return nil, fmt.Errorf("socket required")
			}

			cfg.Host = flag.Arg(0)
		}
	case NetcatModeListen:
		switch cfg.ProtocolConfig.Socket {
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

	cfg.SourcePort = uint16(*sourcePort)
	cfg.SourceHost = *sourceAddr
	cfg.NoDNS = *nodns

	cfg.RecvBuf = *recvBuf
	cfg.SendBuf = *sendBuf

	cfg.NoStdin = *nostdin
	cfg.ScanPorts = *scan
	cfg.KeepListening = *keepListening
	cfg.ExitOnEOF = *exitOnEOF

	if *hexDumpFile != "" {
		cfg.HexFileOutput, err = NewHexFileOutput(*hexDumpFile, *append)
		if err != nil {
			return nil, err
		}
	}
	cfg.Verbose = *verbose

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
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	l := log.New(os.Stdout, "", log.LstdFlags)
	flag.Parse()
	cfg, err := generateConfig()
	if err != nil {
		return err
	}

	nc := &netcat{
		cfg: cfg,
		log: NewLogger(l, cfg),
	}

	if nc.cfg.NetcatMode == NetcatModeListen {
		return nc.runListen()
	}

	return nc.runConnect()
}
