package traefikoidc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// SharedTransportPool manages a pool of shared HTTP transports to prevent connection exhaustion
type SharedTransportPool struct {
	ctx         context.Context
	transports  map[string]*sharedTransport
	cancel      context.CancelFunc
	maxConns    int
	mu          sync.RWMutex
	clientCount int32
	maxClients  int32
}

type sharedTransport struct {
	lastUsed  time.Time
	transport *http.Transport
	refCount  int
	// tlsKey identifies the TLS trust settings (CA pool + InsecureSkipVerify)
	// this transport was built with, so the at-limit fallback only reuses a
	// transport whose TLS configuration matches the caller's.
	tlsKey string
}

var (
	globalTransportPool     *SharedTransportPool
	globalTransportPoolOnce sync.Once
)

// GetGlobalTransportPool returns the singleton transport pool instance
func GetGlobalTransportPool() *SharedTransportPool {
	globalTransportPoolOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		globalTransportPool = &SharedTransportPool{
			transports:  make(map[string]*sharedTransport),
			maxConns:    20, // SECURITY FIX: Reduced from 100 to prevent resource exhaustion
			ctx:         ctx,
			cancel:      cancel,
			clientCount: 0,
			maxClients:  5, // SECURITY FIX: Maximum 5 HTTP clients
		}
		// Start cleanup goroutine with context cancellation
		go globalTransportPool.cleanupIdleTransports(ctx)
	})
	return globalTransportPool
}

// GetOrCreateTransport gets or creates a shared transport with the given config
func (p *SharedTransportPool) GetOrCreateTransport(config HTTPClientConfig) *http.Transport {
	// SECURITY FIX: Check client limit before creating new transport.
	if atomic.LoadInt32(&p.clientCount) >= p.maxClients {
		// At the client limit: only reuse a transport that was built for the
		// SAME config (same TLS trust store). refCount is mutated under the
		// write lock to avoid a data race, and a transport created for a
		// different configuration is never handed back — doing so could apply
		// the wrong (possibly verification-disabled) TLS settings to a request.
		want := tlsConfigKey(config)
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, shared := range p.transports {
			if shared != nil && shared.transport != nil && shared.tlsKey == want {
				shared.refCount++
				shared.lastUsed = time.Now()
				return shared.transport
			}
		}
		// No TLS-compatible transport available; return nil so the caller falls
		// back to a default, certificate-verifying transport rather than one
		// with a different (possibly verification-disabled) trust store.
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	key := p.configKey(config)

	if shared, exists := p.transports[key]; exists {
		shared.refCount++
		shared.lastUsed = time.Now()
		return shared.transport
	}

	// Increment client count
	atomic.AddInt32(&p.clientCount, 1)

	// Create new transport with conservative limits
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
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
			RootCAs:                  config.RootCAs,
			InsecureSkipVerify:       config.InsecureSkipVerify, //nolint:gosec // opt-in, loud warning emitted at plugin startup
		},
		ForceAttemptHTTP2:     config.ForceHTTP2,
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		ExpectContinueTimeout: config.ExpectContinueTimeout,
		MaxIdleConns:          10,               // SECURITY FIX: Further reduced
		MaxIdleConnsPerHost:   2,                // SECURITY FIX: Limited connections
		IdleConnTimeout:       30 * time.Second, // Reduced from 5 minutes
		DisableKeepAlives:     config.DisableKeepAlives,
		MaxConnsPerHost:       5, // SECURITY FIX: Strict limit
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		DisableCompression:    config.DisableCompression,
		WriteBufferSize:       config.WriteBufferSize,
		ReadBufferSize:        config.ReadBufferSize,
	}

	p.transports[key] = &sharedTransport{
		transport: transport,
		refCount:  1,
		lastUsed:  time.Now(),
		tlsKey:    tlsConfigKey(config),
	}

	return transport
}

// ReleaseTransport decrements the reference count for a transport
func (p *SharedTransportPool) ReleaseTransport(transport *http.Transport) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, shared := range p.transports {
		if shared.transport == transport {
			shared.refCount--
			if shared.refCount <= 0 {
				// Mark for cleanup but don't immediately close
				shared.lastUsed = time.Now()
			}
			return
		}
	}
}

// cleanupIdleTransports periodically cleans up unused transports
// Uses two-phase cleanup to minimize lock contention:
// 1. Find candidates while holding read lock
// 2. Remove and close transports with minimal lock duration
func (p *SharedTransportPool) cleanupIdleTransports(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.performCleanup()
		}
	}
}

// performCleanup does the actual cleanup with optimized locking
func (p *SharedTransportPool) performCleanup() {
	now := time.Now()

	// Phase 1: Find candidates while holding read lock (fast)
	p.mu.RLock()
	candidates := make([]string, 0)
	for transportKey, shared := range p.transports {
		// Clean up transports not used for 2 minutes with no references
		if shared.refCount <= 0 && now.Sub(shared.lastUsed) > 2*time.Minute {
			candidates = append(candidates, transportKey)
		}
	}
	p.mu.RUnlock()

	if len(candidates) == 0 {
		return
	}

	// Phase 2: Remove and close each candidate individually
	// This minimizes lock contention and allows concurrent access
	for _, key := range candidates {
		p.mu.Lock()
		shared, exists := p.transports[key]
		if exists && shared.refCount <= 0 && now.Sub(shared.lastUsed) > 2*time.Minute {
			// Remove from map first (releases memory)
			delete(p.transports, key)
			atomic.AddInt32(&p.clientCount, -1)
			p.mu.Unlock()

			// Close idle connections outside the lock (can be slow)
			if shared.transport != nil {
				shared.transport.CloseIdleConnections()
			}
		} else {
			p.mu.Unlock()
		}
	}
}

// configKey generates a unique key for a config
func (p *SharedTransportPool) configKey(config HTTPClientConfig) string {
	// Pool transports by every parameter the built *http.Transport actually
	// consumes. RootCAs and InsecureSkipVerify MUST be part of the key:
	// otherwise a middleware configured with a custom CA would share a
	// transport with one using the system store, silently bypassing its
	// CA configuration. The remaining fields affect connection behavior
	// (HTTP version, compression, keep-alives, timeouts, buffer sizes,
	// dial settings); omitting them would hand a caller a transport built
	// with different settings than it requested (e.g. wrong compression).
	skip := "0"
	if config.InsecureSkipVerify {
		skip = "1"
	}
	return fmt.Sprintf("%d|%d|%p|%s|%d|%d|%d|%v|%v|%v|%d|%d|%d|%d|%d|%d",
		config.MaxConnsPerHost,
		config.MaxIdleConnsPerHost,
		config.RootCAs,
		skip,
		config.DialTimeout,
		config.KeepAlive,
		config.TLSHandshakeTimeout,
		config.ForceHTTP2,
		config.DisableKeepAlives,
		config.DisableCompression,
		config.ResponseHeaderTimeout,
		config.ExpectContinueTimeout,
		config.WriteBufferSize,
		config.ReadBufferSize,
		config.IdleConnTimeout,
		config.MaxIdleConns,
	)
}

// tlsConfigKey identifies only the TLS trust settings of a config — the CA pool
// and the InsecureSkipVerify flag. Two configs with the same tlsConfigKey are
// safe to serve from the same transport even if other (non-TLS) parameters such
// as connection limits differ; configs with different TLS settings are not.
func tlsConfigKey(config HTTPClientConfig) string {
	skip := "0"
	if config.InsecureSkipVerify {
		skip = "1"
	}
	return fmt.Sprintf("%p|%s", config.RootCAs, skip)
}

// Cleanup closes all transports and stops the cleanup goroutine
func (p *SharedTransportPool) Cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Stop the cleanup goroutine
	if p.cancel != nil {
		p.cancel()
	}

	for _, shared := range p.transports {
		shared.transport.CloseIdleConnections()
	}
	p.transports = make(map[string]*sharedTransport)
}

// CreatePooledHTTPClient creates an HTTP client using the shared transport pool
func CreatePooledHTTPClient(config HTTPClientConfig) *http.Client {
	pool := GetGlobalTransportPool()
	transport := pool.GetOrCreateTransport(config)

	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}

	// Configure redirect policy
	maxRedirects := config.MaxRedirects
	if maxRedirects == 0 {
		maxRedirects = 10
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}

	return client
}
