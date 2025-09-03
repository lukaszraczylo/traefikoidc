package traefikoidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// UnifiedTestFramework provides comprehensive test management with automatic cleanup
type UnifiedTestFramework struct {
	t               *testing.T
	mu              sync.Mutex
	cleanupFuncs    []func()
	caches          []*Cache
	tokenCaches     []*TokenCache
	servers         []*httptest.Server
	oidcInstances   []*TraefikOidc
	httpClients     []*http.Client
	backgroundTasks []*BackgroundTask
	goroutineWGs    []*sync.WaitGroup
	contexts        []context.Context
	cancelFuncs     []context.CancelFunc
}

// NewUnifiedTestFramework creates a new test framework with automatic cleanup
func NewUnifiedTestFramework(t *testing.T) *UnifiedTestFramework {
	utf := &UnifiedTestFramework{
		t:               t,
		cleanupFuncs:    make([]func(), 0),
		caches:          make([]*Cache, 0),
		tokenCaches:     make([]*TokenCache, 0),
		servers:         make([]*httptest.Server, 0),
		oidcInstances:   make([]*TraefikOidc, 0),
		httpClients:     make([]*http.Client, 0),
		backgroundTasks: make([]*BackgroundTask, 0),
		goroutineWGs:    make([]*sync.WaitGroup, 0),
		contexts:        make([]context.Context, 0),
		cancelFuncs:     make([]context.CancelFunc, 0),
	}

	// Register cleanup to run even if test panics
	t.Cleanup(func() {
		utf.CleanupAll()
	})

	// Reset global state at start
	resetGlobalState()

	return utf
}

// AddCleanupFunc adds a custom cleanup function
func (utf *UnifiedTestFramework) AddCleanupFunc(fn func()) {
	utf.mu.Lock()
	defer utf.mu.Unlock()
	utf.cleanupFuncs = append(utf.cleanupFuncs, fn)
}

// NewCache creates and tracks a cache for cleanup
func (utf *UnifiedTestFramework) NewCache() *Cache {
	utf.mu.Lock()
	defer utf.mu.Unlock()

	// Use NewLazyCache to avoid immediate background task start
	cache := NewLazyCache()
	utf.caches = append(utf.caches, cache)
	return cache
}

// NewCacheWithLogger creates and tracks a cache with logger
func (utf *UnifiedTestFramework) NewCacheWithLogger(logger *Logger) *Cache {
	utf.mu.Lock()
	defer utf.mu.Unlock()

	// Use lazy cache to avoid immediate background task
	cache := NewLazyCacheWithLogger(logger)
	utf.caches = append(utf.caches, cache)
	return cache
}

// NewTokenCache creates and tracks a token cache for cleanup
func (utf *UnifiedTestFramework) NewTokenCache() *TokenCache {
	utf.mu.Lock()
	defer utf.mu.Unlock()

	// Create token cache with lazy initialization
	tokenCache := &TokenCache{
		cache: NewLazyCache(),
	}
	utf.tokenCaches = append(utf.tokenCaches, tokenCache)
	return tokenCache
}

// NewHTTPTestServer creates and tracks an httptest server
func (utf *UnifiedTestFramework) NewHTTPTestServer(handler http.Handler) *httptest.Server {
	utf.mu.Lock()
	defer utf.mu.Unlock()

	server := httptest.NewServer(handler)
	utf.servers = append(utf.servers, server)
	return server
}

// NewHTTPClient creates and tracks an HTTP client
func (utf *UnifiedTestFramework) NewHTTPClient() *http.Client {
	utf.mu.Lock()
	defer utf.mu.Unlock()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:    2,
			IdleConnTimeout: 5 * time.Second,
		},
	}
	utf.httpClients = append(utf.httpClients, client)
	return client
}

// NewContext creates and tracks a context with cancel
func (utf *UnifiedTestFramework) NewContext() context.Context {
	utf.mu.Lock()
	defer utf.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	utf.contexts = append(utf.contexts, ctx)
	utf.cancelFuncs = append(utf.cancelFuncs, cancel)
	return ctx
}

// NewWaitGroup creates and tracks a wait group
func (utf *UnifiedTestFramework) NewWaitGroup() *sync.WaitGroup {
	utf.mu.Lock()
	defer utf.mu.Unlock()

	wg := &sync.WaitGroup{}
	utf.goroutineWGs = append(utf.goroutineWGs, wg)
	return wg
}

// NewBackgroundTask creates and tracks a background task
func (utf *UnifiedTestFramework) NewBackgroundTask(name string, interval time.Duration, taskFunc func(), logger *Logger) *BackgroundTask {
	utf.mu.Lock()
	defer utf.mu.Unlock()

	task := NewBackgroundTask(name, interval, taskFunc, logger)
	utf.backgroundTasks = append(utf.backgroundTasks, task)
	return task
}

// AddOIDCInstance tracks a TraefikOidc instance for cleanup
func (utf *UnifiedTestFramework) AddOIDCInstance(oidc *TraefikOidc) *TraefikOidc {
	utf.mu.Lock()
	defer utf.mu.Unlock()

	utf.oidcInstances = append(utf.oidcInstances, oidc)
	return oidc
}

// CleanupAll performs comprehensive cleanup of all tracked resources
func (utf *UnifiedTestFramework) CleanupAll() {
	utf.mu.Lock()
	defer utf.mu.Unlock()

	utf.t.Logf("Starting unified test framework cleanup...")

	// Cancel all contexts first to signal shutdown
	for _, cancel := range utf.cancelFuncs {
		if cancel != nil {
			cancel()
		}
	}

	// Stop all background tasks
	for _, task := range utf.backgroundTasks {
		if task != nil {
			task.Stop()
		}
	}

	// Close all OIDC instances
	for _, oidc := range utf.oidcInstances {
		if oidc != nil {
			if err := oidc.Close(); err != nil {
				utf.t.Logf("Error closing OIDC instance: %v", err)
			}
		}
	}

	// Close all token caches
	for _, tc := range utf.tokenCaches {
		if tc != nil && tc.cache != nil {
			tc.cache.Close()
		}
	}

	// Close all caches
	for _, c := range utf.caches {
		if c != nil {
			c.Close()
		}
	}

	// Close all HTTP servers
	for _, s := range utf.servers {
		if s != nil {
			s.Close()
		}
	}

	// Close idle connections in HTTP clients
	for _, client := range utf.httpClients {
		if client != nil && client.Transport != nil {
			if transport, ok := client.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
		}
	}

	// Wait for all goroutines with timeout
	for _, wg := range utf.goroutineWGs {
		if wg != nil {
			done := make(chan struct{})
			go func(wg *sync.WaitGroup) {
				wg.Wait()
				close(done)
			}(wg)

			select {
			case <-done:
				// Goroutines finished
			case <-time.After(5 * time.Second):
				utf.t.Logf("Timeout waiting for goroutines to finish")
			}
		}
	}

	// Run custom cleanup functions
	for _, fn := range utf.cleanupFuncs {
		if fn != nil {
			fn()
		}
	}

	// Reset global state
	resetGlobalState()

	utf.t.Logf("Unified test framework cleanup completed")
}

// EnhancedTestSuite extends TestSuite with UnifiedTestFramework
type EnhancedTestSuite struct {
	*TestSuite
	*UnifiedTestFramework
}

// NewEnhancedTestSuite creates a test suite with automatic resource management
func NewEnhancedTestSuite(t *testing.T) *EnhancedTestSuite {
	utf := NewUnifiedTestFramework(t)

	ts := &TestSuite{
		t:   t,
		utf: utf,
	}

	ets := &EnhancedTestSuite{
		TestSuite:            ts,
		UnifiedTestFramework: utf,
	}

	return ets
}

// Setup initializes the enhanced test suite with automatic cleanup
func (ets *EnhancedTestSuite) Setup() {
	var err error

	// Generate RSA key
	ets.rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		ets.TestSuite.t.Fatalf("Failed to generate RSA key: %v", err)
	}
	ets.rsaPublicKey = &ets.rsaPrivateKey.PublicKey

	// Generate EC key
	ets.ecPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		ets.TestSuite.t.Fatalf("Failed to generate EC key: %v", err)
	}

	// Create JWK for RSA public key
	jwk := JWK{
		Kty: "RSA",
		Kid: "test-key-id",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(ets.rsaPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigIntToBytes(big.NewInt(int64(ets.rsaPublicKey.E)))),
	}
	jwks := &JWKSet{
		Keys: []JWK{jwk},
	}

	// Create mock JWK cache
	ets.mockJWKCache = &MockJWKCache{
		JWKS: jwks,
		Err:  nil,
	}

	// Create test JWT token
	now := time.Now()
	ets.token, err = createTestJWT(ets.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Add(-2 * time.Minute).Unix(),
		"nbf":   now.Add(-2 * time.Minute).Unix(),
		"sub":   "test-subject",
		"email": "user@example.com",
		"nonce": "test-nonce",
		"jti":   generateRandomString(16),
	})
	if err != nil {
		ets.TestSuite.t.Fatalf("Failed to create test JWT: %v", err)
	}

	// Create session manager
	logger := NewLogger("info")
	ets.sessionManager, _ = NewSessionManager("test-secret-key-that-is-at-least-32-bytes", false, "", logger)

	// Create WaitGroup for the OIDC instance
	goroutineWG := ets.NewWaitGroup()

	// Create TraefikOidc instance with tracked resources
	ets.tOidc = &TraefikOidc{
		issuerURL:               "https://test-issuer.com",
		clientID:                "test-client-id",
		clientSecret:            "test-client-secret",
		jwkCache:                ets.mockJWKCache,
		jwksURL:                 "https://test-jwks-url.com",
		revocationURL:           "https://revocation-endpoint.com",
		limiter:                 rate.NewLimiter(rate.Every(time.Second), 10),
		tokenBlacklist:          ets.NewCache(),      // Use framework's tracked cache
		tokenCache:              ets.NewTokenCache(), // Use framework's tracked token cache
		logger:                  logger,
		allowedUserDomains:      map[string]struct{}{"example.com": {}},
		excludedURLs:            map[string]struct{}{"/favicon": {}},
		httpClient:              ets.NewHTTPClient(), // Use framework's tracked HTTP client
		redirURLPath:            "/callback",
		logoutURLPath:           "/callback/logout",
		tokenURL:                "https://test-issuer.com/token",
		extractClaimsFunc:       extractClaims,
		initComplete:            make(chan struct{}),
		sessionManager:          ets.sessionManager,
		goroutineWG:             goroutineWG,
		ctx:                     ets.NewContext(), // Use framework's tracked context
		tokenCleanupStopChan:    make(chan struct{}),
		metadataRefreshStopChan: make(chan struct{}),
	}
	close(ets.tOidc.initComplete)

	ets.tOidc.tokenVerifier = ets.tOidc
	ets.tOidc.jwtVerifier = ets.tOidc

	// Set default mock exchanger
	ets.tOidc.tokenExchanger = &MockTokenExchanger{
		ExchangeCodeFunc: func(ctx context.Context, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error) {
			return &TokenResponse{
				IDToken:      ets.token,
				AccessToken:  ets.token,
				RefreshToken: "default-refresh-token",
				ExpiresIn:    3600,
			}, nil
		},
		RefreshTokenFunc: func(refreshToken string) (*TokenResponse, error) {
			return nil, fmt.Errorf("default mock: refresh not expected")
		},
		RevokeTokenFunc: func(token, tokenType string) error {
			return nil
		},
	}

	// Track the OIDC instance for cleanup
	ets.AddOIDCInstance(ets.tOidc)
}

// CreateMockOIDCServer creates a mock OIDC server with automatic cleanup
func (utf *UnifiedTestFramework) CreateMockOIDCServer(issuerURL string) *httptest.Server {
	server := utf.NewHTTPTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
				"issuer": "%s",
				"authorization_endpoint": "%s/auth",
				"token_endpoint": "%s/token",
				"userinfo_endpoint": "%s/userinfo",
				"jwks_uri": "%s/keys",
				"revocation_endpoint": "%s/revoke"
			}`, issuerURL, issuerURL, issuerURL, issuerURL, issuerURL, issuerURL)
		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"keys": [{
					"kty": "RSA",
					"kid": "test-key-id",
					"use": "sig",
					"n": "test-n-value",
					"e": "AQAB"
				}]
			}`))
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"access_token": "test-access-token",
				"id_token": "` + ValidIDToken + `",
				"refresh_token": "test-refresh-token",
				"token_type": "bearer",
				"expires_in": 3600
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server
}
