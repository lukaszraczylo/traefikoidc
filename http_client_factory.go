package traefikoidc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// HTTPClientConfig provides configuration for creating HTTP clients
type HTTPClientConfig struct {
	// Timeout for the entire request
	Timeout time.Duration
	// MaxRedirects allowed (0 means follow Go's default of 10)
	MaxRedirects int
	// UseCookieJar enables cookie jar for the client
	UseCookieJar bool
	// Connection settings
	DialTimeout           time.Duration
	KeepAlive             time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	ExpectContinueTimeout time.Duration
	IdleConnTimeout       time.Duration
	// Connection pool settings
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int
	// Buffer settings
	WriteBufferSize int
	ReadBufferSize  int
	// Feature flags
	ForceHTTP2         bool
	DisableKeepAlives  bool
	DisableCompression bool
}

// DefaultHTTPClientConfig returns the default configuration for general use
func DefaultHTTPClientConfig() HTTPClientConfig {
	return HTTPClientConfig{
		Timeout:               5 * time.Second,
		MaxRedirects:          10,
		UseCookieJar:          false,
		DialTimeout:           5 * time.Second,
		KeepAlive:             15 * time.Second,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       5 * time.Second,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   1,
		MaxConnsPerHost:       2,
		WriteBufferSize:       4096,
		ReadBufferSize:        4096,
		ForceHTTP2:            true,
		DisableKeepAlives:     false,
		DisableCompression:    false,
	}
}

// TokenHTTPClientConfig returns configuration optimized for token operations
func TokenHTTPClientConfig() HTTPClientConfig {
	config := DefaultHTTPClientConfig()
	config.MaxRedirects = 50   // Token endpoints may redirect more
	config.UseCookieJar = true // Enable cookie jar for token operations
	return config
}

// HTTPClientFactory provides methods for creating configured HTTP clients
type HTTPClientFactory struct{}

// NewHTTPClientFactory creates a new HTTP client factory
func NewHTTPClientFactory() *HTTPClientFactory {
	return &HTTPClientFactory{}
}

// CreateHTTPClient creates an HTTP client with the given configuration
func (f *HTTPClientFactory) CreateHTTPClient(config HTTPClientConfig) *http.Client {
	// Create transport with configured settings
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   config.DialTimeout,
				KeepAlive: config.KeepAlive,
			}
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     config.ForceHTTP2,
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		ExpectContinueTimeout: config.ExpectContinueTimeout,
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		IdleConnTimeout:       config.IdleConnTimeout,
		DisableKeepAlives:     config.DisableKeepAlives,
		MaxConnsPerHost:       config.MaxConnsPerHost,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		DisableCompression:    config.DisableCompression,
		WriteBufferSize:       config.WriteBufferSize,
		ReadBufferSize:        config.ReadBufferSize,
	}

	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}

	// Configure redirect policy
	maxRedirects := config.MaxRedirects
	if maxRedirects == 0 {
		maxRedirects = 10 // Go's default
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		return nil
	}

	// Add cookie jar if requested
	if config.UseCookieJar {
		jar, _ := cookiejar.New(nil)
		client.Jar = jar
	}

	return client
}

// CreateDefaultClient creates a client with default configuration
func (f *HTTPClientFactory) CreateDefaultClient() *http.Client {
	return f.CreateHTTPClient(DefaultHTTPClientConfig())
}

// CreateTokenClient creates a client optimized for token operations
func (f *HTTPClientFactory) CreateTokenClient() *http.Client {
	return f.CreateHTTPClient(TokenHTTPClientConfig())
}

// Global factory instance for convenience
var globalHTTPClientFactory = NewHTTPClientFactory()

// CreateHTTPClientWithConfig creates an HTTP client with the given configuration
// using the global factory instance
func CreateHTTPClientWithConfig(config HTTPClientConfig) *http.Client {
	return globalHTTPClientFactory.CreateHTTPClient(config)
}

// CreateDefaultHTTPClient creates a default HTTP client using the global factory
func CreateDefaultHTTPClient() *http.Client {
	return globalHTTPClientFactory.CreateDefaultClient()
}

// CreateTokenHTTPClient creates a token HTTP client using the global factory
func CreateTokenHTTPClient() *http.Client {
	return globalHTTPClientFactory.CreateTokenClient()
}
