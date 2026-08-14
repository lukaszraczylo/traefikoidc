package pool

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
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
	if globalTransportPool == nil {
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
	}
	return globalTransportPool
}

// resetGlobalTransportPoolForTest clears the process-global transport pool so the
// next call to GetTransportPool returns a fresh instance, and cancels the
// current pool's cleanup goroutine. Required for order-independent tests that
// replace the global pool: the singleton is sync.Once-guarded, so without a
// reset a consumed Once leaves GetTransportPool returning nil and later callers
// panic on a nil receiver (see TestCreateHTTPClient_Fallback).
func resetGlobalTransportPoolForTest() {
	if globalTransportPool != nil && globalTransportPool.cancel != nil {
		globalTransportPool.cancel()
	}
	transportPoolOnce = sync.Once{}
	globalTransportPool = nil
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
		return p.getExistingTransport(config)
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
func (p *TransportPool) getExistingTransport(config TransportConfig) *http.Transport {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Prefer a transport whose TLS settings (verification, min version)
	// match the request. Reusing a mismatched transport at cap could hand a
	// strict-verifying caller an InsecureSkipVerify transport (silent cert
	// verification bypass) or an insecure caller a verifying one (R146).
	for _, shared := range p.transports {
		if shared != nil && shared.transport != nil && p.tlsMatches(config, shared.config) {
			atomic.AddInt32(&shared.refCount, 1)
			shared.lastUsed = time.Now()
			return shared.transport
		}
	}
	// No TLS-matching pooled transport: return nil so the caller falls back
	// to a safe basic client (http.DefaultTransport verifies certs) rather
	// than receiving a mismatched peer. Bounded by the cap (R146).
	return nil
}

// tlsMatches reports whether two transports share the same TLS posture
// (certificate verification and minimum protocol version), normalized for
// createTransport's 0-means-TLS1.2 default.
func (p *TransportPool) tlsMatches(a, b TransportConfig) bool {
	amin, bmin := a.MinTLSVersion, b.MinTLSVersion
	if amin == 0 {
		amin = tls.VersionTLS12
	}
	if bmin == 0 {
		bmin = tls.VersionTLS12
	}
	return a.InsecureSkipVerify == b.InsecureSkipVerify && amin == bmin
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

	// Write the int fields verbatim, not byte()s: a config value >=256 would
	// otherwise truncate and make two distinct configs collide on one key,
	// silently sharing a single transport with the wrong settings.
	sb.WriteString(strconv.Itoa(config.MaxConnsPerHost))
	sb.WriteByte('|')
	sb.WriteString(strconv.Itoa(config.MaxIdleConnsPerHost))
	sb.WriteByte('|')
	sb.WriteString(strconv.Itoa(config.MaxIdleConns))
	sb.WriteByte('|')
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
	// Include MinTLSVersion and every timeout so two configs differing only
	// in TLS minimum version or timeouts do NOT collide on one key and
	// silently share a transport with whoever-arrived-first's settings
	// (a possible TLS-version downgrade). Mirror http_client_pool.go's
	// all-field key (R146).
	sb.WriteByte('|')
	if config.MinTLSVersion == 0 {
		sb.WriteString("tls12")
	} else {
		sb.WriteString(strconv.Itoa(int(config.MinTLSVersion)))
	}
	for _, d := range []time.Duration{
		config.DialTimeout,
		config.TLSHandshakeTimeout,
		config.ResponseHeaderTimeout,
		config.ExpectContinueTimeout,
		config.IdleConnTimeout,
		config.KeepAlive,
	} {
		sb.WriteByte('|')
		sb.WriteString(strconv.FormatInt(int64(d), 10))
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
