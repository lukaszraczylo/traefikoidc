package pool

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// TransportPool manages a pool of shared HTTP transports to prevent connection exhaustion
// and resource leaks. It provides centralized management of HTTP client transports with
// proper lifecycle management and security controls.
type TransportPool struct {
	ctx         context.Context
	transports  map[string]*sharedTransport
	cancel      context.CancelFunc
	maxConns    int
	mu          sync.RWMutex
	clientCount int32
	maxClients  int32
}

// sharedTransport wraps an HTTP transport with reference counting
type sharedTransport struct {
	lastUsed  time.Time
	transport *http.Transport
	config    TransportConfig
	refCount  int32
}

// TransportConfig defines configuration for HTTP transports
type TransportConfig struct {
	MaxConnsPerHost       int
	WriteBufferSize       int
	ResponseHeaderTimeout time.Duration
	ExpectContinueTimeout time.Duration
	IdleConnTimeout       time.Duration
	KeepAlive             time.Duration
	TLSHandshakeTimeout   time.Duration
	MaxIdleConns          int
	DialTimeout           time.Duration
	MaxIdleConnsPerHost   int
	ReadBufferSize        int
	MinTLSVersion         uint16
	ForceHTTP2            bool
	DisableCompression    bool
	InsecureSkipVerify    bool
	DisableKeepAlives     bool
}

var (
	// globalTransportPool is the singleton transport pool instance
	globalTransportPool *TransportPool
	// transportPoolOnce ensures single initialization
	transportPoolOnce sync.Once
)

// GetTransportPool returns the global transport pool instance
func GetTransportPool() *TransportPool {
	transportPoolOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		globalTransportPool = &TransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20,
			ctx:         ctx,
			cancel:      cancel,
			clientCount: 0,
			maxClients:  5,
		}
		go globalTransportPool.cleanupRoutine(ctx)
	})
	return globalTransportPool
}

// DefaultTransportConfig returns a secure default configuration
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		DialTimeout:           30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		KeepAlive:             30 * time.Second,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   2,
		MaxConnsPerHost:       5,
		ForceHTTP2:            true,
		DisableKeepAlives:     false,
		DisableCompression:    false,
		WriteBufferSize:       4096,
		ReadBufferSize:        4096,
		InsecureSkipVerify:    false,
		MinTLSVersion:         tls.VersionTLS12,
	}
}

// GetTransport gets or creates a shared transport with the given config
func (p *TransportPool) GetTransport(config TransportConfig) *http.Transport {
	// Check client limit
	if atomic.LoadInt32(&p.clientCount) >= p.maxClients {
		return p.getExistingTransport()
	}

	key := p.configKey(config)

	// Fast path: check with read lock
	p.mu.RLock()
	if shared, exists := p.transports[key]; exists {
		atomic.AddInt32(&shared.refCount, 1)
		shared.lastUsed = time.Now()
		p.mu.RUnlock()
		return shared.transport
	}
	p.mu.RUnlock()

	// Slow path: create new transport
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if shared, exists := p.transports[key]; exists {
		atomic.AddInt32(&shared.refCount, 1)
		shared.lastUsed = time.Now()
		return shared.transport
	}

	// Create new transport
	transport := p.createTransport(config)
	shared := &sharedTransport{
		transport: transport,
		refCount:  1,
		lastUsed:  time.Now(),
		config:    config,
	}

	p.transports[key] = shared
	atomic.AddInt32(&p.clientCount, 1)

	return transport
}

// ReleaseTransport decrements the reference count for a transport
func (p *TransportPool) ReleaseTransport(transport *http.Transport) {
	if transport == nil {
		return
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, shared := range p.transports {
		if shared.transport == transport {
			count := atomic.AddInt32(&shared.refCount, -1)
			if count <= 0 {
				shared.lastUsed = time.Now()
			}
			return
		}
	}
}

// getExistingTransport returns any available transport when limit is reached
func (p *TransportPool) getExistingTransport() *http.Transport {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, shared := range p.transports {
		if shared != nil && shared.transport != nil {
			atomic.AddInt32(&shared.refCount, 1)
			shared.lastUsed = time.Now()
			return shared.transport
		}
	}
	return nil
}

// createTransport creates a new HTTP transport with the given config
func (p *TransportPool) createTransport(config TransportConfig) *http.Transport {
	// Set secure defaults
	if config.MinTLSVersion == 0 {
		config.MinTLSVersion = tls.VersionTLS12
	}

	tlsConfig := &tls.Config{
		MinVersion: config.MinTLSVersion,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		// #nosec G402 -- PreferServerCipherSuites is deprecated in Go 1.17+ but setting it is harmless
		PreferServerCipherSuites: true,
		// #nosec G402 -- InsecureSkipVerify is configurable for testing/dev environments
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   config.DialTimeout,
				KeepAlive: config.KeepAlive,
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:       tlsConfig,
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
}

// configKey generates a unique key for a transport config
func (p *TransportPool) configKey(config TransportConfig) string {
	// Create a simple key based on critical parameters
	sb := Get().GetStringBuilder()
	defer Get().PutStringBuilder(sb)

	sb.WriteByte(byte(config.MaxConnsPerHost))
	sb.WriteByte(byte(config.MaxIdleConnsPerHost))
	sb.WriteByte(byte(config.MaxIdleConns))
	if config.ForceHTTP2 {
		sb.WriteByte(1)
	} else {
		sb.WriteByte(0)
	}
	if config.DisableKeepAlives {
		sb.WriteByte(1)
	} else {
		sb.WriteByte(0)
	}
	if config.DisableCompression {
		sb.WriteByte(1)
	} else {
		sb.WriteByte(0)
	}
	if config.InsecureSkipVerify {
		sb.WriteByte(1)
	} else {
		sb.WriteByte(0)
	}

	return sb.String()
}

// cleanupRoutine periodically cleans up unused transports
func (p *TransportPool) cleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.cleanup()
			return
		case <-ticker.C:
			p.cleanupIdle()
		}
	}
}

// cleanupIdle removes idle transports
func (p *TransportPool) cleanupIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for key, shared := range p.transports {
		refCount := atomic.LoadInt32(&shared.refCount)
		if refCount <= 0 && now.Sub(shared.lastUsed) > 2*time.Minute {
			shared.transport.CloseIdleConnections()
			delete(p.transports, key)
			atomic.AddInt32(&p.clientCount, -1)
		}
	}
}

// cleanup closes all transports
func (p *TransportPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, shared := range p.transports {
		shared.transport.CloseIdleConnections()
	}
	p.transports = make(map[string]*sharedTransport)
	atomic.StoreInt32(&p.clientCount, 0)
}

// Shutdown gracefully shuts down the transport pool
func (p *TransportPool) Shutdown() {
	if p.cancel != nil {
		p.cancel()
	}
}

// Stats returns transport pool statistics
type TransportPoolStats struct {
	ActiveTransports int
	TotalClients     int32
	MaxClients       int32
}

// GetStats returns current pool statistics
func (p *TransportPool) GetStats() TransportPoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	activeCount := 0
	for _, shared := range p.transports {
		if atomic.LoadInt32(&shared.refCount) > 0 {
			activeCount++
		}
	}

	return TransportPoolStats{
		ActiveTransports: activeCount,
		TotalClients:     atomic.LoadInt32(&p.clientCount),
		MaxClients:       p.maxClients,
	}
}

// CreateHTTPClient creates an HTTP client using the transport pool
func CreateHTTPClient(config TransportConfig, timeout time.Duration) *http.Client {
	pool := GetTransportPool()
	transport := pool.GetTransport(config)

	if transport == nil {
		// Fallback to a basic client if pool is exhausted
		return &http.Client{
			Timeout: timeout,
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	// Configure redirect policy
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	return client
}
