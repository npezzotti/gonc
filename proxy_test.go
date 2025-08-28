package main

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/armon/go-socks5"
	"golang.org/x/net/proxy"
)

func createMockHTTPProxy(t *testing.T, hasAuth, shouldFail bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			t.Errorf("expected CONNECT method, got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if hasAuth {
			auth := r.Header.Get("Proxy-Authorization")
			expectedAuth := "Basic " + base64.RawStdEncoding.EncodeToString([]byte("user:pass"))
			if auth != expectedAuth {
				t.Errorf("expected auth %s, got %s", expectedAuth, auth)
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
		}

		if shouldFail {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func Test_httpDialerFactory(t *testing.T) {
	tcases := []struct {
		name string
		url  *url.URL
	}{
		{
			name: "without auth",
			url: &url.URL{
				Scheme: "http",
				Host:   "proxy.example.com:8080",
			},
		},
		{
			name: "with auth",
			url: &url.URL{
				Scheme: "http",
				Host:   "proxy.example.com:8080",
				User:   url.UserPassword("user", "pass"),
			},
		},
	}
	for _, tt := range tcases {
		t.Run(tt.name, func(t *testing.T) {
			d, err := httpDialerFactory(tt.url, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			httpDialer, ok := d.(*httpDialer)
			if !ok {
				t.Fatalf("expected dialer to be of type *httpDialer, got %T", d)
			}

			if httpDialer.proxyUrl != tt.url {
				t.Errorf("expected proxyUrl to be %v, got %v", tt.url, httpDialer.proxyUrl)
			}

			if tt.url.User == nil && httpDialer.auth != "" {
				t.Errorf("expected no auth, got %q", httpDialer.auth)
			}

			if tt.url.User != nil {
				pass, _ := tt.url.User.Password()
				authStr := tt.url.User.Username() + ":" + pass
				if base64.StdEncoding.EncodeToString([]byte(authStr)) != httpDialer.auth {
					t.Errorf("expected auth to be %q, got %q", base64.StdEncoding.EncodeToString([]byte(authStr)), httpDialer.auth)
				}
			}
		})
	}
}

func Test_httpDialer_Dial(t *testing.T) {
	tcases := []struct {
		name, auth string
		shouldFail bool
	}{
		{
			name: "without auth",
		},
		{
			name: "with auth",
			auth: "dXNlcjpwYXNz", // base64 for "user:pass"
		},
		{
			name:       "bad response code",
			shouldFail: true,
		},
	}

	for _, tt := range tcases {
		t.Run(tt.name, func(t *testing.T) {
			testServer := createMockHTTPProxy(t, tt.auth != "", tt.shouldFail)
			t.Cleanup(func() {
				testServer.Close()
			})

			d := &httpDialer{
				proxyUrl: &url.URL{
					Scheme: "http",
					Host:   testServer.Listener.Addr().String(),
				},
				auth: tt.auth,
			}

			conn, err := d.Dial("tcp", testServer.URL)
			t.Cleanup(func() {
				if conn != nil {
					conn.Close()
				}
			})
			if tt.shouldFail {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conn == nil {
				t.Fatal("expected non-nil connection")
			}
		})
	}
}

type mockHttpDialer struct{}

func mockHttpDialerFactory(u *url.URL, d proxy.Dialer) (proxy.Dialer, error) {
	return &mockHttpDialer{}, nil
}

func (d *mockHttpDialer) Dial(network, addr string) (net.Conn, error) {
	return &mockNetConn{}, nil
}
func Test_dialProxy_http(t *testing.T) {
	tcases := []struct {
		name, auth string
	}{
		{
			name: "without auth",
			auth: "",
		},
		{
			name: "with auth",
			auth: "dXNlcjpwYXNz", // base64 for "user:pass"
		},
	}
	proxy.RegisterDialerType("http", mockHttpDialerFactory)
	t.Cleanup(func() {
		// Reset to the original factory after the test
		proxy.RegisterDialerType("http", httpDialerFactory)
	})

	for _, tt := range tcases {
		t.Run(tt.name, func(t *testing.T) {
			proxyServer := createMockHTTPProxy(t, tt.auth != "", false)
			t.Cleanup(func() {
				proxyServer.Close()
			})

			n := &netcat{
				cfg: &Config{
					ProxyType: ProxyTypeHTTP,
					ProxyAddr: proxyServer.Listener.Addr().String(),
					ProxyAuth: tt.auth,
				},
			}

			conn, err := n.dialProxy("tcp", "example.com:80")
			t.Cleanup(func() {
				if conn != nil {
					conn.Close()
				}
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conn == nil {
				t.Fatal("expected non-nil connection")
			}
		})
	}
}

func Test_dialProxy_socks5(t *testing.T) {
	tcases := []struct {
		name, auth string
	}{
		{
			name: "without auth",
		},
		{
			name: "with auth",
			auth: "user:pass",
		},
	}

	remoteServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test TCP server: %v", err)
	}
	t.Cleanup(func() {
		remoteServer.Close()
	})

	for _, tt := range tcases {
		t.Run(tt.name, func(t *testing.T) {
			go func() {
				conn, _ := remoteServer.Accept()
				conn.Close()
			}()

			proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to start test SOCKS5 proxy listener: %v", err)
			}
			t.Cleanup(func() {
				proxyListener.Close()
			})

			config := &socks5.Config{}
			if tt.auth != "" {
				config.Credentials = &socks5.StaticCredentials{"user": "pass"}
			}
			proxyServer, err := socks5.New(config)
			if err != nil {
				t.Fatalf("failed to create SOCKS5 proxy server: %v", err)
			}

			go func() {
				proxyConn, _ := proxyListener.Accept()
				defer proxyConn.Close()
				proxyServer.ServeConn(proxyConn)
			}()

			n := &netcat{
				cfg: &Config{
					ProxyType: ProxyTypeSOCKS5,
					ProxyAddr: proxyListener.Addr().String(),
					ProxyAuth: tt.auth,
				},
			}

			conn, err := n.dialProxy("tcp", remoteServer.Addr().String())
			t.Cleanup(func() {
				if conn != nil {
					conn.Close()
				}
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conn == nil {
				t.Fatal("expected non-nil connection")
			}
		})
	}
}

func Test_dialProxy_SOCKS5_invalidAuth(t *testing.T) {
	n := &netcat{
		cfg: &Config{
			ProxyType: ProxyTypeSOCKS5,
			ProxyAuth: "invalid", // missing ':'
		},
	}
	_, err := n.dialProxy("tcp", "example.com:80")
	if err == nil || !strings.Contains(err.Error(), "invalid SOCKS5 proxy authentication format") {
		t.Fatalf("expected invalid auth format error, got: %v", err)
	}
}

func Test_dialProxy_SOCKS4_notSupported(t *testing.T) {
	n := &netcat{
		cfg: &Config{
			ProxyType: ProxyTypeSOCKS4,
		},
	}
	_, err := n.dialProxy("tcp", "example.com:80")
	if err == nil || !strings.Contains(err.Error(), "SOCKS4 proxy is not supported") {
		t.Fatalf("expected SOCKS4 not supported error, got: %v", err)
	}
}

func Test_dialProxy_unsupportedProxyType(t *testing.T) {
	n := &netcat{
		cfg: &Config{
			ProxyType: "unsupported",
		},
	}
	_, err := n.dialProxy("tcp", "example.com:80")
	if err == nil || !strings.Contains(err.Error(), "unsupported proxy type") {
		t.Fatalf("expected unsupported proxy type error, got: %v", err)
	}
}
