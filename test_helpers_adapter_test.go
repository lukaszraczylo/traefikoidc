package traefikoidc

import (
	"net/http/httptest"
	"sync"
	"testing"
)

// testWriter is an io.Writer that writes to test log
// lint:ignore U1000 Kept for potential future use
/*
type testWriter struct {
	t *testing.T
}

func (w *testWriter) Write(p []byte) (n int, err error) {
	w.t.Log(string(p))
	return len(p), nil
}
*/

// Test helper adapters for the new test files

// resetGlobalState resets all global singletons to prevent test interference
// nolint:unused // Kept for potential future use in integration tests
/*
func resetGlobalState() {
	// Reset global task registry first to stop all background tasks
	ResetGlobalTaskRegistry()

	// Give tasks a moment to stop
	time.Sleep(10 * time.Millisecond)

	// Reset and cleanup replay cache - this should work now that tasks are stopped
	cleanupReplayCache()

	// Reset memory pools
	memoryPoolMutex.Lock()
	globalMemoryPools = nil
	memoryPoolOnce = sync.Once{}
	memoryPoolMutex.Unlock()

	// The universal cache manager is a singleton that persists across tests
	// Don't reset it as it causes issues
}
*/

// testCleanup provides comprehensive cleanup for tests to prevent goroutine leaks
type testCleanup struct {
	t       *testing.T
	caches  []CacheInterface
	servers []*httptest.Server
	oidcs   []*TraefikOidc
	mu      sync.Mutex
}

// newTestCleanup creates a new test cleanup helper that automatically registers cleanup
func newTestCleanup(t *testing.T) *testCleanup {
	tc := &testCleanup{
		t:       t,
		caches:  make([]CacheInterface, 0),
		servers: make([]*httptest.Server, 0),
		oidcs:   make([]*TraefikOidc, 0),
	}

	// Register cleanup to run even if test panics
	t.Cleanup(func() {
		tc.cleanupAll()
	})

	return tc
}

// addCache registers a cache for cleanup
func (tc *testCleanup) addCache(c CacheInterface) CacheInterface {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.caches = append(tc.caches, c)
	return c
}

// addTokenCache registers a token cache for cleanup
func (tc *testCleanup) addTokenCache(c *TokenCache) *TokenCache {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	// TokenCache cleanup is handled by the global manager
	// No need to manually close as it's a singleton
	return c
}

// addOIDC registers a TraefikOidc instance for cleanup
//
//lint:ignore U1000 Kept for potential future use
func (tc *testCleanup) addOIDC(o *TraefikOidc) *TraefikOidc {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.oidcs = append(tc.oidcs, o)
	return o
}

// cleanupAll cleans up all registered resources
func (tc *testCleanup) cleanupAll() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Close all caches
	for _, c := range tc.caches {
		if c != nil {
			c.Close()
		}
	}

	// Close all servers
	for _, s := range tc.servers {
		if s != nil {
			s.Close()
		}
	}

	// Close all OIDC instances
	for _, o := range tc.oidcs {
		if o != nil {
			// Close caches within the OIDC instance
			if o.tokenCache != nil && o.tokenCache.cache != nil {
				o.tokenCache.cache.Close()
			}
			if o.tokenBlacklist != nil {
				o.tokenBlacklist.Close()
			}
			// Call Close if it exists
			o.Close()
		}
	}

	// Reset global state - commented out as resetGlobalState is unused
	// resetGlobalState()
}

// createTestConfig creates a config with all required fields populated for testing
// nolint:unused // Kept for potential future use in integration tests
/*
func createTestConfig() *Config {
	config := CreateConfig()
	config.ProviderURL = "https://test-provider.com"
	config.ClientID = "test-client-id"
	config.ClientSecret = "test-client-secret"
	config.SessionEncryptionKey = "test-encryption-key-32-characters"
	config.CallbackURL = "/oauth2/callback"
	return config
}
*/

// setupTestOIDCMiddleware creates a test OIDC middleware instance with mock servers
// nolint:unused // Kept for potential future use in integration tests
/*
func setupTestOIDCMiddleware(t *testing.T, config *Config) (*TraefikOidc, *httptest.Server) {
	// Reset global state to ensure test isolation
	resetGlobalState()

	// Create mock OIDC server
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 serverURL,
				"authorization_endpoint": serverURL + "/auth",
				"token_endpoint":         serverURL + "/token",
				"userinfo_endpoint":      serverURL + "/userinfo",
				"jwks_uri":               serverURL + "/keys",
				"revocation_endpoint":    serverURL + "/revoke",
			})
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
	serverURL = server.URL

	// Create middleware bypassing validation like main tests do
	// Create a logger that outputs to test log
	logger := &Logger{
		logError: log.New(&testWriter{t}, "ERROR: ", 0),
		logInfo:  log.New(&testWriter{t}, "INFO: ", 0),
		logDebug: log.New(&testWriter{t}, "DEBUG: ", 0),
	}
	sessionManager, _ := NewSessionManager(config.SessionEncryptionKey, false, "", "", logger)

	// Create next handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Set default paths
	callbackPath := config.CallbackURL
	if callbackPath == "" {
		callbackPath = "/oauth2/callback"
	}
	logoutPath := config.LogoutURL
	if logoutPath == "" {
		logoutPath = callbackPath + "/logout"
	}

	// Set default post logout redirect URI to match the actual implementation
	postLogoutRedirectURI := config.PostLogoutRedirectURI
	if postLogoutRedirectURI == "" {
		postLogoutRedirectURI = "/" // Default to root path like the actual implementation
	}

	// Use test URLs that won't be blocked by validation
	testIssuerURL := "https://test-provider.example.com"
	testAuthURL := testIssuerURL + "/auth"
	testTokenURL := testIssuerURL + "/token"
	testJWKSURL := testIssuerURL + "/keys"

	// Create WaitGroup for background goroutines
	var wg sync.WaitGroup

	// Create context with cancel for proper cleanup
	ctx, cancel := context.WithCancel(context.Background())

	// Create TraefikOidc instance directly
	oidc := &TraefikOidc{
		next:                  nextHandler,
		issuerURL:             testIssuerURL,
		clientID:              config.ClientID,
		audience:              config.ClientID,
		clientSecret:          config.ClientSecret,
		redirURLPath:          callbackPath,
		logoutURLPath:         logoutPath,
		postLogoutRedirectURI: postLogoutRedirectURI,
		limiter:               rate.NewLimiter(rate.Every(time.Second), 10),
		tokenBlacklist:        NewCache(),
		tokenCache:            NewTokenCache(),
		logger:                logger,
		excludedURLs:          make(map[string]struct{}),
		httpClient:            &http.Client{},
		authURL:               testAuthURL,
		tokenURL:              testTokenURL,
		jwksURL:               testJWKSURL,
		initComplete:          make(chan struct{}),
		sessionManager:        sessionManager,
		extractClaimsFunc:     extractClaims,
		enablePKCE:            config.EnablePKCE,
		refreshGracePeriod:    time.Duration(config.RefreshGracePeriodSeconds) * time.Second,
		revocationURL:         config.RevocationURL,
		endSessionURL:         config.OIDCEndSessionURL,
		scopes:                config.Scopes,
		forceHTTPS:            config.ForceHTTPS,
		allowedUserDomains:    make(map[string]struct{}),
		jwkCache:              NewJWKCache(),
		metadataCache:         NewMetadataCache(nil),
		ctx:                   ctx,
		cancelFunc:            cancel,
		goroutineWG:           &wg,
		providerURL:           serverURL,
	}

	// Process excluded URLs
	for _, url := range config.ExcludedURLs {
		oidc.excludedURLs[url] = struct{}{}
	}

	// Set default excluded URLs
	oidc.excludedURLs["/favicon"] = struct{}{}
	oidc.excludedURLs["/favicon.ico"] = struct{}{}

	// Close init channel
	close(oidc.initComplete)

	// Set verifiers
	oidc.tokenVerifier = oidc
	oidc.jwtVerifier = oidc
	oidc.tokenExchanger = oidc // Set tokenExchanger to self

	// Set default refresh grace period if not set or negative
	if config.RefreshGracePeriodSeconds <= 0 {
		oidc.refreshGracePeriod = 60 * time.Second
	}

	// Set authentication initiation function
	oidc.initiateAuthenticationFunc = func(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
		// Generate CSRF token and nonce
		csrfToken := uuid.NewString()
		nonce := uuid.NewString()

		// Store in session
		session.SetCSRF(csrfToken)
		session.SetNonce(nonce)

		// Store the original path
		session.SetIncomingPath(req.URL.RequestURI())

		// Handle PKCE if enabled
		var codeChallenge string
		if oidc.enablePKCE {
			verifier, _ := generateCodeVerifier()
			session.SetCodeVerifier(verifier)
			codeChallenge = deriveCodeChallenge(verifier)
		}

		// Save session
		session.Save(req, rw)

		// Build auth URL
		authURL := oidc.buildAuthURL(redirectURL, csrfToken, nonce, codeChallenge)

		// Redirect
		http.Redirect(rw, req, authURL, http.StatusFound)
	}

	// Set scopes if not set
	if len(oidc.scopes) == 0 {
		oidc.scopes = []string{"openid", "profile", "email"}
	}

	return oidc, server
}
*/

// createMockJWT creates a mock JWT token for testing - adapter for existing tests
// nolint:unused // Kept for potential future use in integration tests
/*
func createMockJWT(t *testing.T, sub, email string) string {
	return ValidIDToken
}
*/

// createTestSession creates a properly initialized SessionData for testing
func createTestSession() *SessionData {
	// Create a minimal session manager for testing
	logger := newNoOpLogger()
	sessionManager, _ := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, logger)

	// Create a test request
	req := httptest.NewRequest("GET", "/", nil)

	// Get a session from the manager
	session, _ := sessionManager.GetSession(req)
	return session
}

// injectSessionIntoRequest saves the session and adds the resulting cookies to the request
// nolint:unused // Kept for potential future use in integration tests
/*
func injectSessionIntoRequest(t *testing.T, req *http.Request, session *SessionData) {
	// Create a response recorder to capture cookies
	rec := httptest.NewRecorder()

	// Save the session (this sets cookies)
	if err := session.Save(req, rec); err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Add the cookies to the request
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
}
*/
