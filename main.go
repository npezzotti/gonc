package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func init() {
	log.SetFlags(0)
	log.SetPrefix("gonc: ")
}

var (
	version = "dev"
)

type flags struct {
	listen        bool
	udp           bool
	useUnix       bool
	ipv4_only     bool
	ipv6_only     bool
	nostdin       bool
	keepListening bool
	noShutdown    bool
	noDNS         bool
	sourceAddr    string
	sourcePort    uint
	timeout       string
	scan          bool
	telnet        bool
	verbose       bool
	interval      string
	ssl           bool
	sslCert       string
	sslKey        string
	sslNoVerify   bool
	sslTrustFile  string
	sslCiphers    string
	sslServerName string
	sslAlpn       string
	proxyAddr     string
	proxyType     string
	proxyAuth     string
	versionFlag   bool
}

func main() {
	if err := run(log.Default()); err != nil {
		log.Fatalln(err)
	}
}

func run(l *log.Logger) error {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	f := &flags{}
	fs.BoolVar(&f.listen, "listen", false, "listen for an incoming connection rather than initiate a connection to a remote host.")
	fs.BoolVar(&f.udp, "udp", false, "use UDP instead of the default option of TCP. For UNIX-domain sockets, use a datagram socket instead of a stream socket.  "+
		"If a UNIX-domain socket is used, a temporary receiving socket is created unless the -source flag is given.")
	fs.BoolVar(&f.useUnix, "unix", false, "use Unix Domain Sockets")
	fs.BoolVar(&f.ipv4_only, "ipv4", false, "use IPv4 addresses only")
	fs.BoolVar(&f.ipv6_only, "ipv6", false, "use IPv6 addresses only")
	fs.BoolVar(&f.nostdin, "nostdin", false, "do not attempt to read from stdin")
	fs.BoolVar(&f.keepListening, "keep", false, "when a connection is completed, listen for another one.  Requires -listen.")
	fs.BoolVar(&f.noShutdown, "no-shutdown", false, "do not shutdown the network socket after EOF on the input.")
	fs.BoolVar(&f.noDNS, "no-dns", false, "do not resolve hostnames to IP addresses")
	fs.StringVar(&f.sourceAddr, "sourceaddr", "", "Set the source address to send packets from, which is useful on machines with multiple interfaces.  "+
		"For UNIX-domain datagram sockets, specifies the local temporary socket file to create and use so that datagrams can be received.")
	fs.UintVar(&f.sourcePort, "port", 0, "the source port gonc should use, subject to privilege restrictions and availability.")
	fs.StringVar(&f.timeout, "timeout", "0s", "connections which cannot be established or are idle timeout "+
		"after timeout seconds. Has no effect on the -listen option, i.e. gonc will listen forever for a connection, "+
		"with or without the -w fs.")
	fs.BoolVar(&f.scan, "scan", false, "scan for listening daemons, without sending any data to them.")
	fs.BoolVar(&f.telnet, "telnet", false, "send RFC 854 DON'T and WON'T responses to RFC 854 DO and WILL requests. "+
		"This makes it possible to script telnet sessions.")
	fs.BoolVar(&f.verbose, "verbose", false, "enable more verbose output.")
	fs.StringVar(&f.interval, "interval", "0s", "Sleep for interval seconds between lines of text sent and received. Also causes a delay time between connections to multiple ports.")
	fs.BoolVar(&f.ssl, "ssl", false, "Connect or listen with SSL")
	fs.StringVar(&f.sslCert, "cert", "", "Specify SSL certificate file (PEM) for listening")
	fs.StringVar(&f.sslKey, "key", "", "Specify SSL private key (PEM) for listening")
	fs.BoolVar(&f.sslNoVerify, "no-verify", false, "Do not verify trust and domain name of certificates")
	fs.StringVar(&f.sslTrustFile, "trustfile", "", "PEM file containing trusted SSL certificates")
	fs.StringVar(&f.sslCiphers, "ciphers", "", "Comma-separated list of SSL cipher suites")
	fs.StringVar(&f.sslServerName, "servername", "", "Request distinct server name (SNI)")
	fs.StringVar(&f.sslAlpn, "alpn", "", "Comma-separated list of ALPN protocols to use")
	fs.StringVar(&f.proxyAddr, "proxy", "", "Specify address of host to proxy through.")
	fs.StringVar(&f.proxyType, "proxy-type", "5", "Use proxy_protocol when talking to the proxy server. "+
		"Supported protocols are 5 (SOCKS v.5) and connect (HTTPS proxy). If the protocol is not specified, SOCKS version 5 is used.")
	fs.StringVar(&f.proxyAuth, "proxy-auth", "", "Specify proxy authentication credentials (username:password).")
	fs.BoolVar(&f.versionFlag, "version", false, "Print version and exit.")
	fs.Parse(os.Args[1:])

	if f.versionFlag {
		fmt.Println("Version:", version)
		return nil
	}

	cfg, err := parseConfig(f, flag.Args())
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
	addr, err := cfg.Address()
	if err != nil {
		return err
	}

	if nc.cfg.NetcatMode == NetcatModeListen {
		return nc.runListen(network, addr)
	}

	return nc.runConnect(network, addr)
}
