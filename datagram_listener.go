package main

import (
	"fmt"
	"net"
)

type DatagramListener struct {
	conn net.Conn
}

func NewDatagramListener(protocol, laddr string) (*DatagramListener, error) {
	var conn net.Conn
	switch protocol {
	case "udp", "udp4", "udp6":
		udpAddr, err := net.ResolveUDPAddr(protocol, laddr)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve udp address: %w", err)
		}
		conn, err = net.ListenUDP(protocol, udpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on udp address: %w", err)
		}
	case "unixgram":
		unixAddr, err := net.ResolveUnixAddr(protocol, laddr)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve unixgram address: %w", err)
		}
		conn, err = net.ListenUnixgram("unixgram", unixAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on unixgram address: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
	return &DatagramListener{conn: conn}, nil
}

func (l *DatagramListener) Accept() (net.Conn, error) {
	return l.conn, nil
}

func (l *DatagramListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *DatagramListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return nil
}
