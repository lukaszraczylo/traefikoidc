package traefikoidc

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
	// Apply the same zero-value defaults as CreateHTTPClient so a partially
	// populated config never yields an unbounded client/transport, and so the
	// pool cache key reflects normalized values (configKey). Bounded here,
	// before the client-count gate, so both the gate and the key see
	// normalized timeouts.
	applyHTTPClientDefaults(&config)
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
		// No TLS-compatible transport available. Returning nil would make the
		// caller fall back to http.DefaultTransport, silently dropping the
		// configured RootCAs / InsecureSkipVerify — custom-CA TLS would
		// break and self-signed skip-verify would be lost (R95). Build and
		// return the correctly-configured transport instead; honoring TLS
		// settings takes precedence over the soft client cap.
		t := newSharedTransport(config)
		p.transports[p.configKey(config)] = &sharedTransport{
			transport: t,
			refCount:  1,
			lastUsed:  time.Now(),
			tlsKey:    want,
		}
		atomic.AddInt32(&p.clientCount, 1)
		return t
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

	transport := newSharedTransport(config)

	p.transports[key] = &sharedTransport{
		transport: transport,
		refCount:  1,
		lastUsed:  time.Now(),
		tlsKey:    tlsConfigKey(config),
	}

	return transport
}

// newSharedTransport builds a properly-configured *http.Transport from the
// given config, enforcing TLS 1.2+ and secure cipher suites. Shared by the
// normal acquisition path and the at-cap fallback so the TLS settings are
// NEVER silently dropped (the at-cap fallback previously returned nil,
// making the caller fall back to http.DefaultTransport and lose the
// configured RootCAs / InsecureSkipVerify — R95).
func newSharedTransport(config HTTPClientConfig) *http.Transport {
	return &http.Transport{
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

// Cleanup closes all transports, resets the pool, and restarts the cleanup
// goroutine so the (singleton) pool remains fully usable afterwards. Prior
// to R125, Cleanup canceled the cleanup goroutine but never restarted it
// and left clientCount unreset: a reused singleton then had a permanently
// dead cleaner (idle conns never pruned) and a stale count (the soft
// maxClients cap keyed off it was wrong after reuse).
func (p *SharedTransportPool) Cleanup() {
	p.mu.Lock()
	for _, shared := range p.transports {
		if shared != nil && shared.transport != nil {
			shared.transport.CloseIdleConnections()
		}
	}
	p.transports = make(map[string]*sharedTransport)
	atomic.StoreInt32(&p.clientCount, 0)
	oldCancel := p.cancel
	ctx, cancel := context.WithCancel(context.Background())
	p.ctx = ctx
	p.cancel = cancel
	p.mu.Unlock()

	if oldCancel != nil {
		oldCancel()
	}
	go p.cleanupIdleTransports(ctx)
}

// CreatePooledHTTPClient creates an HTTP client using the shared transport pool
func CreatePooledHTTPClient(config HTTPClientConfig) *http.Client {
	// Apply the same zero-value defaults as CreateHTTPClient so a partially
	// populated config still gets a bounded overall request Timeout.
	applyHTTPClientDefaults(&config)
	pool := GetGlobalTransportPool()
	transport := pool.GetOrCreateTransport(config)

	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}

	// Honor the cookie-jar option, matching CreateHTTPClient
	// (http_client_factory.go). Without this, token/OIDC clients built
	// through the pool would silently drop UseCookieJar (config no-effect),
	// so cookies set by the auth server on token/refresh responses were
	// never stored or re-sent.
	if config.UseCookieJar {
		jar, _ := cookiejar.New(nil) // Safe to ignore: nil options rarely fail
		client.Jar = jar
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
