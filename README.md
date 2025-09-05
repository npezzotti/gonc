# gonc

## Overview

**gonc** is a netcat-like utility implemented in Go. It enables simple TCP/UDP networking tasks such as sending and receiving data, making it useful for debugging, file transfers, and scripting network operations.

## Features

- Can function as both client and server
- TCP and UDP protocols
- Unix sockets
- SSL
- Proxy
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

| Option              | Description                        |
|---------------------|------------------------------------|
| `-listen`           | Listen mode (server)               |
| `-port <port>`      | Port to listen on or connect to    |
| `-udp`              | Use UDP instead of TCP             |
| `-unix`             | Use unix domain sockets            |
| `-h`                | Show help message                  |

## Example

Send a message:

```sh
echo "Hello, world!" | ./gonc -p 1234 localhost
```
