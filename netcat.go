package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type netcat struct {
	cfg *Config
	log *Logger
}

type HalfCloser interface {
	CloseRead() error
	CloseWrite() error
}

func copyPackets(conn net.PacketConn, listen bool) error {
	var wg sync.WaitGroup
	var remoteAddr net.Addr
	var err error
	var n int

	if listen {
		buf := make([]byte, 1024)
		n, remoteAddr, err = conn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("read from conn: %w", err)
		}

		log.Printf("Receiving packets from %s\n", remoteAddr.String())

		if _, err := os.Stdout.Write(buf[:n]); err != nil {
			log.Printf("write stdout: %s\n", err)
			return err
		}
	}

	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer func() {
			conn.Close() // Close the connection to signal the reader goroutine to stop.
			wg.Done()
		}()

		stdin := make(chan []byte)
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := os.Stdin.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Printf("read stdin: %s\n", err)
					}
					break
				}
				stdin <- buf[:n]
			}
			close(stdin)
		}()

		for {
			select {
			case data, ok := <-stdin:
				if !ok {
					return
				}
				if listen {
					if _, err = conn.WriteTo(data, remoteAddr); err != nil {
						if !errors.Is(err, net.ErrClosed) {
							log.Printf("write to: %s", err)
						}
						return
					}
				} else {
					_, err = conn.(net.Conn).Write(data)
					if err != nil {
						log.Printf("write: %s", err)
						return
					}
				}
			case <-stop:
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
		}()

		buf := make([]byte, 1024)
		for {
			select {
			case <-stop:
				return
			default:
				n, clientAddr, err := conn.ReadFrom(buf)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						log.Printf("read from conn: %s", err)
					}
					return
				}

				if listen && clientAddr.String() != remoteAddr.String() {
					// drop packets from other clients
					continue
				}

				if _, err := os.Stdout.Write(buf[:n]); err != nil {
					log.Printf("write stdout: %s", err)
					return
				}
			}
		}
	}()

	doneChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneChan) // Close the channel to signal that all goroutines are done.
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		close(stop) // signal the writer goroutine to stop
		<-doneChan  // wait for the goroutines to finish
	case <-doneChan:
	}

	return nil
}

func setSendBuffer(conn net.Conn, size int) error {
	if size > 0 {
		switch c := conn.(type) {
		case *net.UDPConn:
			return c.SetWriteBuffer(size)
		case *net.TCPConn:
			return c.SetWriteBuffer(size)
		case *net.UnixConn:
			return c.SetWriteBuffer(size)
		default:
			return fmt.Errorf("unsupported connection type for setting send buffer: %T", conn)
		}
	}
	return nil
}

func setReceiveBuffer(conn net.Conn, size int) error {
	if size > 0 {
		switch c := conn.(type) {
		case *net.UDPConn:
			return c.SetReadBuffer(size)
		case *net.TCPConn:
			return c.SetReadBuffer(size)
		case *net.UnixConn:
			return c.SetReadBuffer(size)
		default:
			return fmt.Errorf("unsupported connection type for setting receive buffer: %T", conn)
		}
	}

	return nil
}
