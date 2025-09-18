package httpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"sync/atomic"
	"time"
)

// Config provides configuration for creating HTTP clients
type Config struct {
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
	// TLS configuration
	TLSConfig *tls.Config
}

// ClientType defines the type of HTTP client for optimized behavior
type ClientType string

const (
	ClientTypeDefault ClientType = "default"
	ClientTypeToken   ClientType = "token"
	ClientTypeAPI     ClientType = "api"
	ClientTypeProxy   ClientType = "proxy"
)

// PresetConfigs provides pre-configured settings for different client types
var PresetConfigs = map[ClientType]Config{
	ClientTypeDefault: {
		Timeout:               10 * time.Second, // Reduced from 30s to prevent slowloris attacks
		MaxRedirects:          5,                // Reduced from 10 to prevent redirect loops
		UseCookieJar:          false,
		DialTimeout:           3 * time.Second,
		KeepAlive:             15 * time.Second,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       5 * time.Second,
		MaxIdleConns:          20, // Reduced from 100 to limit resource usage
		MaxIdleConnsPerHost:   2,  // Reduced from 10 to prevent connection exhaustion
		MaxConnsPerHost:       5,  // Reduced from 10 to limit concurrent connections
		WriteBufferSize:       4096,
		ReadBufferSize:        4096,
		ForceHTTP2:            true,
		DisableKeepAlives:     false,
		DisableCompression:    false,
	},
	ClientTypeToken: {
		Timeout:               10 * time.Second,
		MaxRedirects:          50, // Token endpoints may redirect more
		UseCookieJar:          true,
		DialTimeout:           3 * time.Second,
		KeepAlive:             15 * time.Second,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       5 * time.Second,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   2,
		MaxConnsPerHost:       5,
		WriteBufferSize:       4096,
		ReadBufferSize:        4096,
		ForceHTTP2:            true,
		DisableKeepAlives:     false,
		DisableCompression:    false,
	},
	ClientTypeAPI: {
		Timeout:               30 * time.Second, // Longer for API operations
		MaxRedirects:          10,
		UseCookieJar:          false,
		DialTimeout:           5 * time.Second,
		KeepAlive:             30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   5,
		MaxConnsPerHost:       10,
		WriteBufferSize:       8192,
		ReadBufferSize:        8192,
		ForceHTTP2:            true,
		DisableKeepAlives:     false,
		DisableCompression:    false,
	},
	ClientTypeProxy: {
		Timeout:               60 * time.Second, // Proxy needs longer timeouts
		MaxRedirects:          0,                // Proxy should not follow redirects
		UseCookieJar:          false,
		DialTimeout:           10 * time.Second,
		KeepAlive:             30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       20,
		WriteBufferSize:       16384,
		ReadBufferSize:        16384,
		ForceHTTP2:            true,
		DisableKeepAlives:     false,
		DisableCompression:    true, // Proxy should not modify content
	},
}

// Factory provides methods for creating configured HTTP clients
type Factory struct {
	pool   *TransportPool
	logger Logger
}

// Logger interface for HTTP client operations
type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...interface{})
	Info(msg string)
	Infof(format string, args ...interface{})
	Error(msg string)
	Errorf(format string, args ...interface{})
}

var (
	globalFactory     *Factory
	globalFactoryOnce sync.Once
)

// GetGlobalFactory returns the singleton HTTP client factory
func GetGlobalFactory(logger Logger) *Factory {
	globalFactoryOnce.Do(func() {
		globalFactory = NewFactory(logger)
	})
	return globalFactory
}

// NewFactory creates a new HTTP client factory
func NewFactory(logger Logger) *Factory {
	if logger == nil {
		logger = &noOpLogger{}
	}
	return &Factory{
		pool:   GetGlobalTransportPool(),
		logger: logger,
	}
}

// CreateClient creates an HTTP client with the specified configuration
func (f *Factory) CreateClient(config Config) (*http.Client, error) {
	// Validate configuration
	if err := f.ValidateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Apply TLS configuration if not provided
	if config.TLSConfig == nil {
		config.TLSConfig = f.createSecureTLSConfig()
	}

	// Get or create transport from pool
	transport := f.pool.GetOrCreateTransport(config)
	if transport == nil {
		return nil, fmt.Errorf("failed to create transport: client limit exceeded")
	}

	// Create HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	// Configure redirect policy
	if config.MaxRedirects > 0 {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
			}
			return nil
		}
	}

	// Add cookie jar if requested
	if config.UseCookieJar {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create cookie jar: %w", err)
		}
		client.Jar = jar
	}

	f.logger.Debugf("Created HTTP client with config: timeout=%v, maxRedirects=%d", config.Timeout, config.MaxRedirects)
	return client, nil
}

// CreateClientWithPreset creates an HTTP client using a preset configuration
func (f *Factory) CreateClientWithPreset(clientType ClientType) (*http.Client, error) {
	config, ok := PresetConfigs[clientType]
	if !ok {
		return nil, fmt.Errorf("unknown client type: %s", clientType)
	}
	return f.CreateClient(config)
}

// CreateDefault creates a default HTTP client
func (f *Factory) CreateDefault() (*http.Client, error) {
	return f.CreateClientWithPreset(ClientTypeDefault)
}

// CreateToken creates an HTTP client optimized for token operations
func (f *Factory) CreateToken() (*http.Client, error) {
	return f.CreateClientWithPreset(ClientTypeToken)
}

// CreateAPI creates an HTTP client optimized for API operations
func (f *Factory) CreateAPI() (*http.Client, error) {
	return f.CreateClientWithPreset(ClientTypeAPI)
}

// CreateProxy creates an HTTP client optimized for proxy operations
func (f *Factory) CreateProxy() (*http.Client, error) {
	return f.CreateClientWithPreset(ClientTypeProxy)
}

// ValidateConfig validates HTTP client configuration parameters
func (f *Factory) ValidateConfig(config *Config) error {
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
	if config.MaxConnsPerHost > 200 {
		return fmt.Errorf("MaxConnsPerHost too high (max 200): %d", config.MaxConnsPerHost)
	}

	// Validate timeouts
	if config.Timeout < 0 {
		return fmt.Errorf("timeout cannot be negative")
	}
	if config.Timeout > 5*time.Minute {
		return fmt.Errorf("timeout too long (max 5 minutes): %v", config.Timeout)
	}

	// Validate buffer sizes
	if config.WriteBufferSize < 0 || config.ReadBufferSize < 0 {
		return fmt.Errorf("buffer sizes cannot be negative")
	}
	if config.WriteBufferSize > 1024*1024 || config.ReadBufferSize > 1024*1024 {
		return fmt.Errorf("buffer sizes too large (max 1MB)")
	}

	return nil
}

// createSecureTLSConfig creates a secure TLS configuration
func (f *Factory) createSecureTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12, // SECURITY: Enforce TLS 1.2 minimum
		MaxVersion: tls.VersionTLS13, // Support up to TLS 1.3
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites (automatically selected when TLS 1.3 is negotiated)
			// TLS 1.2 secure cipher suites
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		InsecureSkipVerify:       false, // SECURITY: Always verify certificates
		PreferServerCipherSuites: false, // Let client choose best cipher
	}
}

// TransportPool manages a pool of shared HTTP transports
type TransportPool struct {
	mu         sync.RWMutex
	transports map[string]*sharedTransport
	maxConns   int
	ctx        context.Context
	cancel     context.CancelFunc

	// Resource limits
	clientCount int32 // Track total HTTP clients
	maxClients  int32 // Limit total clients
}

type sharedTransport struct {
	transport *http.Transport
	refCount  int32
	lastUsed  time.Time
	config    Config
}

var (
	globalTransportPool     *TransportPool
	globalTransportPoolOnce sync.Once
)

// GetGlobalTransportPool returns the singleton transport pool instance
func GetGlobalTransportPool() *TransportPool {
	globalTransportPoolOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		globalTransportPool = &TransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20, // Reduced from 100 to prevent resource exhaustion
			ctx:         ctx,
			cancel:      cancel,
			clientCount: 0,
			maxClients:  5, // Maximum 5 HTTP clients
		}
		// Start cleanup goroutine with context cancellation
		go globalTransportPool.cleanupIdleTransports(ctx)
	})
	return globalTransportPool
}

// GetOrCreateTransport gets or creates a shared transport with the given config
func (p *TransportPool) GetOrCreateTransport(config Config) *http.Transport {
	// Check client limit before creating new transport
	if atomic.LoadInt32(&p.clientCount) >= p.maxClients {
		// Try to return existing transport if limit reached
		p.mu.RLock()
		defer p.mu.RUnlock()
		for _, shared := range p.transports {
			if shared != nil && shared.transport != nil {
				atomic.AddInt32(&shared.refCount, 1)
				shared.lastUsed = time.Now()
				return shared.transport
			}
		}
		// If no transport available, return nil
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	key := p.configKey(config)

	if shared, exists := p.transports[key]; exists {
		atomic.AddInt32(&shared.refCount, 1)
		shared.lastUsed = time.Now()
		return shared.transport
	}

	// Create new transport
	transport := p.createTransport(config)

	p.transports[key] = &sharedTransport{
		transport: transport,
		refCount:  1,
		lastUsed:  time.Now(),
		config:    config,
	}

	atomic.AddInt32(&p.clientCount, 1)
	return transport
}

// createTransport creates a new HTTP transport with the given configuration
func (p *TransportPool) createTransport(config Config) *http.Transport {
	// Create secure TLS config if not provided
	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		}
	}

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   config.DialTimeout,
			KeepAlive: config.KeepAlive,
		}).DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		ExpectContinueTimeout: config.ExpectContinueTimeout,
		IdleConnTimeout:       config.IdleConnTimeout,
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		MaxConnsPerHost:       config.MaxConnsPerHost,
		WriteBufferSize:       config.WriteBufferSize,
		ReadBufferSize:        config.ReadBufferSize,
		ForceAttemptHTTP2:     config.ForceHTTP2,
		DisableKeepAlives:     config.DisableKeepAlives,
		DisableCompression:    config.DisableCompression,
	}
}

// configKey generates a unique key for the configuration
func (p *TransportPool) configKey(config Config) string {
	return fmt.Sprintf("%v-%d-%d-%d-%d-%v-%v-%v",
		config.Timeout,
		config.MaxIdleConns,
		config.MaxIdleConnsPerHost,
		config.MaxConnsPerHost,
		config.MaxRedirects,
		config.ForceHTTP2,
		config.DisableKeepAlives,
		config.DisableCompression,
	)
}

// cleanupIdleTransports periodically cleans up idle transports
func (p *TransportPool) cleanupIdleTransports(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.cleanupIdle()
		}
	}
}

// cleanupIdle removes idle transports with zero references
func (p *TransportPool) cleanupIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	var toRemove []string

	for key, shared := range p.transports {
		if atomic.LoadInt32(&shared.refCount) == 0 && now.Sub(shared.lastUsed) > 10*time.Minute {
			if shared.transport != nil {
				shared.transport.CloseIdleConnections()
			}
			toRemove = append(toRemove, key)
		}
	}

	for _, key := range toRemove {
		delete(p.transports, key)
		atomic.AddInt32(&p.clientCount, -1)
	}
}

// Release decrements the reference count for a transport
func (p *TransportPool) Release(transport *http.Transport) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, shared := range p.transports {
		if shared.transport == transport {
			atomic.AddInt32(&shared.refCount, -1)
			return
		}
	}
}

// Close shuts down the transport pool
func (p *TransportPool) Close() error {
	p.cancel()

	p.mu.Lock()
	defer p.mu.Unlock()

	for key, shared := range p.transports {
		if shared.transport != nil {
			shared.transport.CloseIdleConnections()
		}
		delete(p.transports, key)
	}

	atomic.StoreInt32(&p.clientCount, 0)
	return nil
}

// noOpLogger provides a no-op logger implementation
type noOpLogger struct{}

func (l *noOpLogger) Debug(msg string)                          {}
func (l *noOpLogger) Debugf(format string, args ...interface{}) {}
func (l *noOpLogger) Info(msg string)                           {}
func (l *noOpLogger) Infof(format string, args ...interface{})  {}
func (l *noOpLogger) Error(msg string)                          {}
func (l *noOpLogger) Errorf(format string, args ...interface{}) {}

// Compatibility functions for backward compatibility

// CreateDefaultHTTPClient creates a default HTTP client
func CreateDefaultHTTPClient() *http.Client {
	factory := GetGlobalFactory(nil)
	client, _ := factory.CreateDefault()
	return client
}

// CreateTokenHTTPClient creates an HTTP client optimized for token operations
func CreateTokenHTTPClient() *http.Client {
	factory := GetGlobalFactory(nil)
	client, _ := factory.CreateToken()
	return client
}

// CreateHTTPClientWithConfig creates an HTTP client with custom configuration
func CreateHTTPClientWithConfig(config Config) *http.Client {
	factory := GetGlobalFactory(nil)
	client, _ := factory.CreateClient(config)
	return client
}
