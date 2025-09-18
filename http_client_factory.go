package traefikoidc

import (
	"context"
	"crypto/tls"
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
		Timeout:               10 * time.Second, // SECURITY FIX: Reduced from 30s to prevent slowloris attacks
		MaxRedirects:          5,                // SECURITY FIX: Reduced from 10 to prevent redirect loops
		UseCookieJar:          false,
		DialTimeout:           3 * time.Second, // SECURITY FIX: Reduced from 5s
		KeepAlive:             15 * time.Second,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       5 * time.Second,
		MaxIdleConns:          20, // SECURITY FIX: Reduced from 100 to limit resource usage
		MaxIdleConnsPerHost:   2,  // SECURITY FIX: Reduced from 10 to prevent connection exhaustion
		MaxConnsPerHost:       5,  // SECURITY FIX: Reduced from 10 to limit concurrent connections
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
	config.Timeout = 10 * time.Second // Shorter timeout for token operations
	config.MaxRedirects = 50          // Token endpoints may redirect more
	config.UseCookieJar = true        // Enable cookie jar for token operations
	return config
}

// HTTPClientFactory provides methods for creating configured HTTP clients
type HTTPClientFactory struct{}

// NewHTTPClientFactory creates a new HTTP client factory
func NewHTTPClientFactory() *HTTPClientFactory {
	return &HTTPClientFactory{}
}

// ValidateHTTPClientConfig validates HTTP client configuration parameters
func (f *HTTPClientFactory) ValidateHTTPClientConfig(config *HTTPClientConfig) error {
	// Validate connection pool limits
	if config.MaxIdleConns < 0 {
		return fmt.Errorf("MaxIdleConns cannot be negative: %d", config.MaxIdleConns)
	}
	if config.MaxIdleConns > 1000 {
		return fmt.Errorf("MaxIdleConns too high (max 1000): %d", config.MaxIdleConns)
	}

	if config.MaxIdleConnsPerHost < 0 {
		return fmt.Errorf("MaxIdleConnsPerHost cannot be negative: %d", config.MaxIdleConnsPerHost)
	}
	if config.MaxIdleConnsPerHost > 100 {
		return fmt.Errorf("MaxIdleConnsPerHost too high (max 100): %d", config.MaxIdleConnsPerHost)
	}

	if config.MaxConnsPerHost < 0 {
		return fmt.Errorf("MaxConnsPerHost cannot be negative: %d", config.MaxConnsPerHost)
	}
	if config.MaxConnsPerHost > 100 {
		return fmt.Errorf("MaxConnsPerHost too high (max 100): %d", config.MaxConnsPerHost)
	}

	// Validate that MaxIdleConnsPerHost is not greater than MaxConnsPerHost
	if config.MaxIdleConnsPerHost > config.MaxConnsPerHost && config.MaxConnsPerHost > 0 {
		return fmt.Errorf("MaxIdleConnsPerHost (%d) cannot exceed MaxConnsPerHost (%d)",
			config.MaxIdleConnsPerHost, config.MaxConnsPerHost)
	}

	// Validate timeout values
	if config.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive: %v", config.Timeout)
	}
	if config.Timeout > 5*time.Minute {
		return fmt.Errorf("timeout too high (max 5m): %v", config.Timeout)
	}

	if config.DialTimeout <= 0 {
		return fmt.Errorf("DialTimeout must be positive: %v", config.DialTimeout)
	}
	if config.TLSHandshakeTimeout <= 0 {
		return fmt.Errorf("TLSHandshakeTimeout must be positive: %v", config.TLSHandshakeTimeout)
	}

	return nil
}

// CreateHTTPClient creates an HTTP client with the given configuration
// Validates configuration parameters before creating the client
func (f *HTTPClientFactory) CreateHTTPClient(config HTTPClientConfig) *http.Client {
	// Set defaults for zero values before validation
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.DialTimeout == 0 {
		config.DialTimeout = 5 * time.Second
	}
	if config.TLSHandshakeTimeout == 0 {
		config.TLSHandshakeTimeout = 2 * time.Second
	}
	if config.KeepAlive == 0 {
		config.KeepAlive = 15 * time.Second
	}
	if config.ResponseHeaderTimeout == 0 {
		config.ResponseHeaderTimeout = 3 * time.Second
	}
	if config.ExpectContinueTimeout == 0 {
		config.ExpectContinueTimeout = 1 * time.Second
	}
	if config.IdleConnTimeout == 0 {
		config.IdleConnTimeout = 5 * time.Second
	}
	if config.MaxIdleConns == 0 {
		config.MaxIdleConns = 100
	}
	if config.MaxIdleConnsPerHost == 0 {
		config.MaxIdleConnsPerHost = 10
	}
	if config.MaxConnsPerHost == 0 {
		config.MaxConnsPerHost = 10
	}
	if config.WriteBufferSize == 0 {
		config.WriteBufferSize = 4096
	}
	if config.ReadBufferSize == 0 {
		config.ReadBufferSize = 4096
	}

	// Validate configuration - only fail on critical errors
	if err := f.ValidateHTTPClientConfig(&config); err != nil {
		// Only use default config for critical validation failures
		// For example, if timeout is negative or extremely high
		if config.Timeout <= 0 || config.Timeout > 5*time.Minute {
			config.Timeout = 30 * time.Second
		}
	}
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
		// SECURITY FIX: Enforce TLS 1.2+ and secure cipher suites
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, // Enforce TLS 1.2 minimum
			MaxVersion: tls.VersionTLS13, // Support up to TLS 1.3
			CipherSuites: []uint16{
				// TLS 1.3 cipher suites (automatically selected when TLS 1.3 is negotiated)
				// TLS 1.2 secure cipher suites
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
			InsecureSkipVerify:       false, // Always verify certificates
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
	// Use pooled client to prevent connection exhaustion
	return CreatePooledHTTPClient(DefaultHTTPClientConfig())
}

// CreateTokenHTTPClient creates a token HTTP client using the global factory
func CreateTokenHTTPClient() *http.Client {
	// Use pooled client to prevent connection exhaustion
	return CreatePooledHTTPClient(TokenHTTPClientConfig())
}
