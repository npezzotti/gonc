package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/proxy"
)

func init() {
	proxy.RegisterDialerType("http", httpDialerFactory)
}

type ProxyType string

const (
	ProxyTypeHTTP   ProxyType = "connect"
	ProxyTypeSOCKS4 ProxyType = "4" // Note: SOCKS4 is not supported in this implementation
	ProxyTypeSOCKS5 ProxyType = "5"
)

type httpDialer struct {
	proxyUrl *url.URL
	auth     string
}

func httpDialerFactory(u *url.URL, d proxy.Dialer) (proxy.Dialer, error) {
	var authStr string
	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		authStr = user + ":" + pass
	}

	dialer := &httpDialer{
		proxyUrl: u,
	}

	if authStr != "" {
		dialer.auth = base64.StdEncoding.EncodeToString([]byte(authStr))
	}

	return dialer, nil
}

func (d *httpDialer) Dial(network, addr string) (net.Conn, error) {
	proxyConn, err := net.Dial(network, d.proxyUrl.Host)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: addr},
		Header: http.Header{},
	}

	if d.auth != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+d.auth)
	}

	if err := req.Write(proxyConn); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("write request to proxy: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(proxyConn), req)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("read response from proxy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy error: %s", resp.Status)
	}

	return proxyConn, nil
}

func (n *netcat) dialProxy(network, remoteAddr string) (net.Conn, error) {
	switch n.cfg.ProxyType {
	case ProxyTypeHTTP:
		var proxyAuth string
		if n.cfg.ProxyAuth != "" {
			proxyAuth = n.cfg.ProxyAuth + "@"
		}

		proxyUrl, err := url.Parse(fmt.Sprintf("http://%s%s", proxyAuth, n.cfg.ProxyAddr))
		if err != nil {
			return nil, fmt.Errorf("parse proxy URL: %w", err)
		}

		dialer, err := proxy.FromURL(proxyUrl, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("create proxy dialer: %w", err)
		}

		return dialer.Dial(network, remoteAddr)
	case ProxyTypeSOCKS5:
		var auth *proxy.Auth
		if n.cfg.ProxyAuth != "" {
			authParts := strings.SplitN(n.cfg.ProxyAuth, ":", 2)
			if len(authParts) != 2 {
				return nil, fmt.Errorf("invalid SOCKS5 proxy authentication format, expected 'username:password'")
			}
			auth = &proxy.Auth{
				User:     authParts[0],
				Password: authParts[1],
			}
		}

		dialer, err := proxy.SOCKS5(network, n.cfg.ProxyAddr, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("create SOCKS5 proxy dialer: %w", err)
		}

		return dialer.Dial(network, remoteAddr)
	case ProxyTypeSOCKS4:
		return nil, fmt.Errorf("SOCKS4 proxy is not supported")
	default:
		return nil, fmt.Errorf("unsupported proxy type: %s", n.cfg.ProxyType)
	}
}
