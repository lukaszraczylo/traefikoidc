package traefikoidc

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// SharedTransportPool manages a pool of shared HTTP transports to prevent connection exhaustion
type SharedTransportPool struct {
	mu         sync.RWMutex
	transports map[string]*sharedTransport
	maxConns   int
}

type sharedTransport struct {
	transport *http.Transport
	refCount  int
	lastUsed  time.Time
}

var (
	globalTransportPool     *SharedTransportPool
	globalTransportPoolOnce sync.Once
)

// GetGlobalTransportPool returns the singleton transport pool instance
func GetGlobalTransportPool() *SharedTransportPool {
	globalTransportPoolOnce.Do(func() {
		globalTransportPool = &SharedTransportPool{
			transports: make(map[string]*sharedTransport),
			maxConns:   100, // Total connection limit across all transports
		}
		// Start cleanup goroutine
		go globalTransportPool.cleanupIdleTransports()
	})
	return globalTransportPool
}

// GetOrCreateTransport gets or creates a shared transport with the given config
func (p *SharedTransportPool) GetOrCreateTransport(config HTTPClientConfig) *http.Transport {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := p.configKey(config)

	if shared, exists := p.transports[key]; exists {
		shared.refCount++
		shared.lastUsed = time.Now()
		return shared.transport
	}

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
		ForceAttemptHTTP2:     config.ForceHTTP2,
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		ExpectContinueTimeout: config.ExpectContinueTimeout,
		MaxIdleConns:          20,               // Reduced from 100
		MaxIdleConnsPerHost:   2,                // Reduced from 10
		IdleConnTimeout:       30 * time.Second, // Reduced from 5 minutes
		DisableKeepAlives:     config.DisableKeepAlives,
		MaxConnsPerHost:       5, // Reduced from 10
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		DisableCompression:    config.DisableCompression,
		WriteBufferSize:       config.WriteBufferSize,
		ReadBufferSize:        config.ReadBufferSize,
	}

	p.transports[key] = &sharedTransport{
		transport: transport,
		refCount:  1,
		lastUsed:  time.Now(),
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
func (p *SharedTransportPool) cleanupIdleTransports() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for transportKey, shared := range p.transports {
			// Clean up transports not used for 2 minutes with no references
			if shared.refCount <= 0 && now.Sub(shared.lastUsed) > 2*time.Minute {
				shared.transport.CloseIdleConnections()
				delete(p.transports, transportKey)
			}
		}
		p.mu.Unlock()
	}
}

// configKey generates a unique key for a config
func (p *SharedTransportPool) configKey(config HTTPClientConfig) string {
	// Simple key based on main parameters
	return string(rune(config.MaxConnsPerHost)) + string(rune(config.MaxIdleConnsPerHost))
}

// Cleanup closes all transports and stops the cleanup goroutine
func (p *SharedTransportPool) Cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

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
