# gonc

## Overview

**gonc** is a netcat-like utility implemented in Go. It enables simple TCP/UDP networking tasks such as sending and receiving data, making it useful for debugging, file transfers, and scripting network operations.

## Features

- Can function as both client and server
- TCP and UDP protocols
- Unix sockets
- SSL
- Proxy
- Port scanning
- Verbose logging
- Timeouts
- Telnet
- Interval

## Installation

To build gonc from source:

```sh
git clone https://github.com/npezzotti/gonc.git
cd gonc
make build
```

## Usage

### Start a TCP server

```sh
./gonc -listen 8000
```

### Connect as a TCP client

```sh
./gonc localhost 8000
```

### Send a message

```sh
echo "Hello, world!" | ./gonc localhost 8000
```

### Transfer a file

On the receiver (server):

```sh
./gonc -listen 8000 > received_file.txt
```

On the sender (client):

```sh
./gonc localhost 8000 < file_to_send.txt
```

## Command-line Options
| Option            | Description                                                                                                    |
|-------------------|----------------------------------------------------------------------------------------------------------------|
| `-listen`         | Listen mode (server)                                                                                           |
| `-udp`            | Use UDP instead of TCP                                                                                         |
| `-unix`           | Use Unix domain sockets                                                                                        |
| `-ipv4`           | Use IPv4 addresses only                                                                                        |
| `-ipv6`           | Use IPv6 addresses only                                                                                        |
| `-nostdin`        | Do not attempt to read from stdin                                                                              |
| `-keep`           | When a connection is completed, listen for another one (requires `-listen` and TCP/Unix)                       |
| `-no-shutdown`    | Do not shutdown the network socket after EOF on the input                                                      |
| `-no-dns`         | Do not resolve hostnames to IP addresses                                                                       |
| `-sourceaddr`     | Set the source address to send packets from                                                                    |
| `-port`           | The source port gonc should use, subject to privilege restrictions and availability                            |
| `-timeout`        | Connections which cannot be established or are idle timeout after specified seconds                            |
| `-scan`           | Scan for listening daemons, without sending any data to them                                                   |
| `-telnet`         | Send RFC 854 DON'T and WON'T responses to RFC 854 DO and WILL requests                                         |
| `-verbose`        | Enable more verbose output                                                                                     |
| `-interval`       | Sleep for interval seconds between lines of text sent and received; also functions as delay when scanning ports|
| `-ssl`            | Use SSL                                                                                                        |
| `-cert`           | Specify SSL certificate file (PEM) for listening                                                               |
| `-key`            | Specify SSL private key (PEM) for listening                                                                    |
| `-no-verify`      | Do not verify trust and domain name of certificates                                                            |
| `-trustfile`      | PEM file containing trusted SSL certificates                                                                   |
| `-ciphers`        | Comma-separated list of SSL cipher suites                                                                      |
| `-servername`     | Request distinct server name (SNI)                                                                             |
| `-alpn`           | Comma-separated list of ALPN protocols to use                                                                  |
| `-proxy`          | Specify address of host to proxy through                                                                       |
| `-proxy-type`     | Proxy protocol to use when communicating to the proxy server (`5` for SOCKS v5, `connect` for HTTPS proxy)     |
| `-proxy-auth`     | Specify proxy authentication credentials (`username:password`)                                                 |
| `-version`        | Show version                                                                                                   |
| `-help`           | Show help message                                                                                              |

