package traefikoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// createDefaultHTTPClient creates an HTTP client with optimized settings for OIDC
func createDefaultHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   15 * time.Second, // Reduced timeout
				KeepAlive: 15 * time.Second, // Reduced keepalive
			}
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   5 * time.Second, // Reduced from 10s
		ExpectContinueTimeout: 0,
		MaxIdleConns:          30,               // Reduced from 100
		MaxIdleConnsPerHost:   10,               // Reduced from 100
		IdleConnTimeout:       30 * time.Second, // Reduced from 90s
		DisableKeepAlives:     false,            // Enable connection reuse
		MaxConnsPerHost:       50,               // Limit max connections
	}

	return &http.Client{
		Timeout:   time.Second * 15, // Reduced timeout
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Always follow redirects for OIDC endpoints
			if len(via) >= 50 {
				return fmt.Errorf("stopped after 50 redirects")
			}
			return nil
		},
	}
}

const (
	ConstSessionTimeout      = 86400          // Session timeout in seconds
	defaultBlacklistDuration = 24 * time.Hour // Default duration to blacklist a JTI
)

// TokenVerifier interface for token verification
type TokenVerifier interface {
	VerifyToken(token string) error
}

// JWTVerifier interface for JWT verification
type JWTVerifier interface {
	VerifyJWTSignatureAndClaims(jwt *JWT, token string) error
}

// TokenExchanger defines methods for OIDC token operations
type TokenExchanger interface {
	ExchangeCodeForToken(ctx context.Context, grantType string, codeOrToken string, redirectURL string, codeVerifier string) (*TokenResponse, error)
	GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error)
	RevokeTokenWithProvider(token, tokenType string) error
}

// TraefikOidc is the main struct for the OIDC middleware
type TraefikOidc struct {
	next                       http.Handler
	name                       string
	redirURLPath               string
	logoutURLPath              string
	issuerURL                  string
	revocationURL              string
	jwkCache                   JWKCacheInterface
	metadataCache              *MetadataCache
	tokenBlacklist             *Cache // Replaced TokenBlacklist with generic Cache
	jwksURL                    string
	clientID                   string
	clientSecret               string
	authURL                    string
	tokenURL                   string
	scopes                     []string
	limiter                    *rate.Limiter
	forceHTTPS                 bool
	enablePKCE                 bool
	scheme                     string
	tokenCache                 *TokenCache
	httpClient                 *http.Client
	logger                     *Logger
	tokenVerifier              TokenVerifier
	jwtVerifier                JWTVerifier
	excludedURLs               map[string]struct{}
	allowedUserDomains         map[string]struct{}
	allowedRolesAndGroups      map[string]struct{}
	initiateAuthenticationFunc func(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string)
	// exchangeCodeForTokenFunc   func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) // Replaced by interface
	extractClaimsFunc     func(tokenString string) (map[string]interface{}, error)
	initComplete          chan struct{}
	endSessionURL         string
	postLogoutRedirectURI string
	sessionManager        *SessionManager
	tokenExchanger        TokenExchanger // Added field for mocking
	refreshGracePeriod    time.Duration  // Configurable grace period for proactive refresh
}

// ProviderMetadata holds OIDC provider metadata
type ProviderMetadata struct {
	Issuer        string `json:"issuer"`
	AuthURL       string `json:"authorization_endpoint"`
	TokenURL      string `json:"token_endpoint"`
	JWKSURL       string `json:"jwks_uri"`
	RevokeURL     string `json:"revocation_endpoint"`
	EndSessionURL string `json:"end_session_endpoint"`
}

// defaultExcludedURLs are the paths that are excluded from authentication
var defaultExcludedURLs = map[string]struct{}{
	"/favicon": {},
}

// VerifyToken implements the TokenVerifier interface to verify an OIDC token.
// It performs a complete verification process including:
// 1. Checking the token cache to avoid redundant verifications
// 2. Performing rate limiting and blacklist checks
// 3. Parsing the JWT structure
// 4. Verifying the JWT signature against the JWKS from the provider
// 5. Validating standard JWT claims (iss, aud, exp, etc.)
// 6. Caching the verified token for future requests
//
// Returns nil if the token is valid, or an error describing the validation failure.
func (t *TraefikOidc) VerifyToken(token string) error {
	// Check cache first
	if claims, exists := t.tokenCache.Get(token); exists && len(claims) > 0 {
		t.logger.Debugf("Token found in cache with valid claims; skipping verification")
		return nil
	}

	t.logger.Debugf("Verifying token")

	// Perform pre-verification checks
	if err := t.performPreVerificationChecks(token); err != nil {
		return err
	}

	// Parse the JWT
	jwt, err := parseJWT(token)
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Verify JWT signature and standard claims
	if err := t.VerifyJWTSignatureAndClaims(jwt, token); err != nil {
		return err
	}

	// Cache the verified token
	t.cacheVerifiedToken(token, jwt.Claims)

	// Add JTI to blacklist AFTER successful verification to prevent replay
	if jti, ok := jwt.Claims["jti"].(string); ok && jti != "" {
		// Calculate expiry based on 'exp' claim if available, otherwise use default
		expiry := time.Now().Add(defaultBlacklistDuration)
		if expClaim, expOk := jwt.Claims["exp"].(float64); expOk {
			expTime := time.Unix(int64(expClaim), 0)
			tokenDuration := time.Until(expTime)
			// Use token expiry if longer than default, capped at a reasonable max (e.g., 24h)
			if tokenDuration > defaultBlacklistDuration && tokenDuration < (24*time.Hour) {
				expiry = expTime
			} else if tokenDuration <= 0 {
				// If token already expired but somehow passed verification, use default
				expiry = time.Now().Add(defaultBlacklistDuration)
			} else {
				// Use default if token expiry is shorter or excessively long
				expiry = time.Now().Add(defaultBlacklistDuration)
			}
		}
		// Use Set with a duration. Value 'true' is arbitrary, we only care about existence.
		t.tokenBlacklist.Set(jti, true, time.Until(expiry))
		t.logger.Debugf("Added JTI %s to blacklist cache", jti)
	}

	return nil
}

// performPreVerificationChecks performs rate limiting and blacklist checks
func (t *TraefikOidc) performPreVerificationChecks(token string) error {
	// Enforce rate limiting
	if !t.limiter.Allow() {
		return fmt.Errorf("rate limit exceeded")
	}

	// Check if the raw token string itself is blacklisted (e.g., via explicit revocation)
	if _, exists := t.tokenBlacklist.Get(token); exists {
		return fmt.Errorf("token is blacklisted (raw string) in cache")
	}

	// Also check if the JTI claim is blacklisted (replay detection)
	claims, err := extractClaims(token) // Use existing helper
	if err == nil {                     // Only check JTI if claims could be extracted
		if jti, ok := claims["jti"].(string); ok && jti != "" {
			if _, exists := t.tokenBlacklist.Get(jti); exists {
				// Use a specific error message for replay
				return fmt.Errorf("token replay detected (jti: %s) in cache", jti)
			}
		}
	} // If claims extraction fails, proceed; full validation will catch token issues later.

	return nil
}

// cacheVerifiedToken caches a verified token until its expiration time
func (t *TraefikOidc) cacheVerifiedToken(token string, claims map[string]interface{}) {
	expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
	now := time.Now()
	duration := expirationTime.Sub(now)
	t.tokenCache.Set(token, claims, duration)
}

// VerifyJWTSignatureAndClaims verifies the JWT signature and standard claims
func (t *TraefikOidc) VerifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	t.logger.Debugf("Verifying JWT signature and claims")

	// Get JWKS
	jwks, err := t.jwkCache.GetJWKS(context.Background(), t.jwksURL, t.httpClient)
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Retrieve key ID and algorithm from JWT header
	kid, ok := jwt.Header["kid"].(string)
	if !ok {
		return fmt.Errorf("missing key ID in token header")
	}
	alg, ok := jwt.Header["alg"].(string)
	if !ok {
		return fmt.Errorf("missing algorithm in token header")
	}

	// Find the matching key in JWKS
	var matchingKey *JWK
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			matchingKey = &key
			break
		}
	}
	if matchingKey == nil {
		return fmt.Errorf("no matching public key found for kid: %s", kid)
	}

	// Convert JWK to PEM format
	publicKeyPEM, err := jwkToPEM(matchingKey)
	if err != nil {
		return fmt.Errorf("failed to convert JWK to PEM: %w", err)
	}

	// Verify the signature
	if err := verifySignature(token, publicKeyPEM, alg); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Verify standard claims
	if err := jwt.Verify(t.issuerURL, t.clientID); err != nil {
		return fmt.Errorf("standard claim verification failed: %w", err)
	}

	return nil
}

// New creates a new instance of the OIDC middleware.
// This is the main entry point for the middleware and is called by Traefik when loading the plugin.
// It initializes all components needed for OIDC authentication:
//   - Session management for storing user state
//   - Token caching and blacklisting
//   - JWK caching for signature verification
//   - Rate limiting to prevent abuse
//   - Metadata discovery for OIDC provider endpoints
//
// Parameters:
//   - ctx: Context for initialization operations
//   - next: The next handler in the middleware chain
//   - config: Configuration options for the middleware
//   - name: Identifier for this middleware instance
//
// Returns:
//   - An http.Handler that implements the middleware
//   - An error if initialization fails
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	// Generate default session encryption key if not provided
	if config.SessionEncryptionKey == "" {
		// Generate a fixed key for Traefik Hub testing
		config.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	}

	// Initialize logger
	logger := NewLogger(config.LogLevel)
	// Ensure key meets minimum length requirement
	if len(config.SessionEncryptionKey) < minEncryptionKeyLength {
		if runtime.Compiler == "yaegi" {
			// Set default encryption key for Yaegi (Traefik Plugin Analyzer)
			config.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			logger.Infof("Session encryption key is too short; using default key for analyzer")
		} else {
			return nil, fmt.Errorf("encryption key must be at least %d bytes long", minEncryptionKeyLength)
		}
	}
	// Setup HTTP client
	var httpClient *http.Client
	if config.HTTPClient != nil {
		httpClient = config.HTTPClient
	} else {
		httpClient = createDefaultHTTPClient()
	}
	t := &TraefikOidc{
		next:         next,
		name:         name,
		redirURLPath: config.CallbackURL,
		logoutURLPath: func() string {
			if config.LogoutURL == "" {
				return config.CallbackURL + "/logout"
			}
			return config.LogoutURL
		}(),
		postLogoutRedirectURI: func() string {
			if config.PostLogoutRedirectURI == "" {
				return "/"
			}
			return config.PostLogoutRedirectURI
		}(),
		tokenBlacklist:        NewCache(), // Use generic cache for blacklist
		jwkCache:              &JWKCache{},
		metadataCache:         NewMetadataCache(),
		clientID:              config.ClientID,
		clientSecret:          config.ClientSecret,
		forceHTTPS:            config.ForceHTTPS,
		enablePKCE:            config.EnablePKCE,
		scopes:                config.Scopes,
		limiter:               rate.NewLimiter(rate.Every(time.Second), config.RateLimit),
		tokenCache:            NewTokenCache(),
		httpClient:            httpClient,
		excludedURLs:          createStringMap(config.ExcludedURLs),
		allowedUserDomains:    createStringMap(config.AllowedUserDomains),
		allowedRolesAndGroups: createStringMap(config.AllowedRolesAndGroups),
		initComplete:          make(chan struct{}),
		logger:                logger,
		refreshGracePeriod: func() time.Duration { // Set refresh grace period from config or default
			if config.RefreshGracePeriodSeconds > 0 {
				return time.Duration(config.RefreshGracePeriodSeconds) * time.Second
			}
			return 60 * time.Second // Default to 60 seconds
		}(),
	}

	t.sessionManager, _ = NewSessionManager(config.SessionEncryptionKey, config.ForceHTTPS, t.logger)
	t.extractClaimsFunc = extractClaims
	// t.exchangeCodeForTokenFunc = t.exchangeCodeForToken // Removed, using interface now
	t.initiateAuthenticationFunc = func(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
	}

	// Add default excluded URLs
	for k, v := range defaultExcludedURLs {
		t.excludedURLs[k] = v
	}

	t.tokenVerifier = t
	t.jwtVerifier = t
	t.startTokenCleanup()
	t.tokenExchanger = t // Initialize the interface field to self
	go t.initializeMetadata(config.ProviderURL)

	return t, nil
}

// initializeMetadata discovers and initializes the provider metadata
func (t *TraefikOidc) initializeMetadata(providerURL string) {
	t.logger.Debug("Starting provider metadata discovery")

	// Get metadata from cache or fetch it
	metadata, err := t.metadataCache.GetMetadata(providerURL, t.httpClient, t.logger)
	if err != nil {
		t.logger.Errorf("Failed to get provider metadata: %v", err)
		return
	}

	if metadata != nil {
		t.logger.Debug("Successfully initialized provider metadata")
		t.updateMetadataEndpoints(metadata)

		// Start metadata refresh goroutine
		go t.startMetadataRefresh(providerURL)

		// Only close channel on success
		close(t.initComplete)
		return
	}

	t.logger.Error("Received nil metadata")
}

// updateMetadataEndpoints updates the middleware with metadata endpoints
func (t *TraefikOidc) updateMetadataEndpoints(metadata *ProviderMetadata) {
	t.jwksURL = metadata.JWKSURL
	t.authURL = metadata.AuthURL
	t.tokenURL = metadata.TokenURL
	t.issuerURL = metadata.Issuer
	t.revocationURL = metadata.RevokeURL
	t.endSessionURL = metadata.EndSessionURL
}

// startMetadataRefresh periodically refreshes the OIDC metadata
func (t *TraefikOidc) startMetadataRefresh(providerURL string) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		t.logger.Debug("Refreshing OIDC metadata")
		metadata, err := t.metadataCache.GetMetadata(providerURL, t.httpClient, t.logger)
		if err != nil {
			t.logger.Errorf("Failed to refresh metadata: %v", err)
			continue
		}

		if metadata != nil {
			t.updateMetadataEndpoints(metadata)
			t.logger.Debug("Successfully refreshed metadata")
		}
	}
}

// discoverProviderMetadata fetches the OIDC provider metadata
func discoverProviderMetadata(providerURL string, httpClient *http.Client, l *Logger) (*ProviderMetadata, error) {
	wellKnownURL := strings.TrimSuffix(providerURL, "/") + "/.well-known/openid-configuration"

	maxRetries := 5
	baseDelay := 1 * time.Second
	maxDelay := 30 * time.Second
	totalTimeout := 5 * time.Minute

	start := time.Now()

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if time.Since(start) > totalTimeout {
			l.Errorf("Timeout exceeded while fetching provider metadata")
			return nil, fmt.Errorf("timeout exceeded while fetching provider metadata: %w", lastErr)
		}

		metadata, err := fetchMetadata(wellKnownURL, httpClient)
		if err == nil {
			l.Debug("Provider metadata fetched successfully")
			return metadata, nil
		}

		lastErr = err

		// Exponential backoff
		delay := time.Duration(math.Pow(2, float64(attempt))) * baseDelay
		if delay > maxDelay {
			delay = maxDelay
		}
		l.Debugf("Failed to fetch provider metadata, retrying in %s", delay)
		time.Sleep(delay)
	}

	l.Errorf("Max retries exceeded while fetching provider metadata")
	return nil, fmt.Errorf("max retries exceeded while fetching provider metadata: %w", lastErr)
}

// fetchMetadata fetches metadata from the well-known OIDC configuration endpoint
func fetchMetadata(wellKnownURL string, httpClient *http.Client) (*ProviderMetadata, error) {
	resp, err := httpClient.Get(wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch provider metadata: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("received nil response from provider")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch provider metadata: status code %d", resp.StatusCode)
	}

	var metadata ProviderMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode provider metadata: %w", err)
	}

	return &metadata, nil
}

// ServeHTTP is the main handler for the middleware that processes all HTTP requests.
// It implements the http.Handler interface and performs the following operations:
// 1. Waits for OIDC provider metadata initialization to complete
// 2. Checks if the requested URL is in the excluded list (bypassing authentication)
// 3. Retrieves or creates a user session
// 4. Handles special paths like callback and logout URLs
// 5. Verifies authentication status and token validity
// 6. Refreshes tokens that are about to expire
// 7. Validates user email domains, roles, and groups against configured restrictions
// 8. Sets appropriate headers for downstream services
// 9. Applies security headers to responses
// 10. Forwards the authenticated request to the next handler
func (t *TraefikOidc) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	select {
	case <-t.initComplete:
		if t.issuerURL == "" {
			t.logger.Error("OIDC provider metadata initialization failed")
			http.Error(rw, "OIDC provider metadata initialization failed - please check provider availability", http.StatusServiceUnavailable)
			return
		}
	case <-req.Context().Done():
		t.logger.Debug("Request cancelled")
		http.Error(rw, "Request cancelled", http.StatusServiceUnavailable)
		return
	case <-time.After(30 * time.Second):
		t.logger.Error("Timeout waiting for OIDC initialization")
		http.Error(rw, "Timeout waiting for OIDC provider initialization - please try again", http.StatusServiceUnavailable)
		return
	}

	// Check if URL is excluded
	if t.determineExcludedURL(req.URL.Path) {
		t.logger.Debugf("Request path %s excluded by configuration, bypassing OIDC", req.URL.Path)
		t.next.ServeHTTP(rw, req)
		return
	}

	// Check if the request expects Server-Sent Events
	acceptHeader := req.Header.Get("Accept")
	if strings.Contains(acceptHeader, "text/event-stream") {
		t.logger.Debugf("Request accepts text/event-stream (%s), bypassing OIDC", acceptHeader)
		t.next.ServeHTTP(rw, req)
		return
	}

	// Get session
	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Error getting session: %v", err)

		// Obtain a new session and clear any residual session cookies
		session, _ = t.sessionManager.GetSession(req)
		session.Clear(req, rw)

		// Build redirect URL
		scheme := t.determineScheme(req)
		host := t.determineHost(req)
		redirectURL := buildFullURL(scheme, host, t.redirURLPath)

		// Initiate authentication
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	// Build redirect URL
	scheme := t.determineScheme(req)
	host := t.determineHost(req)
	redirectURL := buildFullURL(scheme, host, t.redirURLPath)

	// Handle special URLs
	if req.URL.Path == t.logoutURLPath {
		t.handleLogout(rw, req)
		return
	}

	if req.URL.Path == t.redirURLPath {
		t.handleCallback(rw, req, redirectURL)
		return
	}

	// Check authentication status
	authenticated, needsRefresh, expired := t.isUserAuthenticated(session)

	if expired {
		t.handleExpiredToken(rw, req, session, redirectURL)
		return
	}

	if !authenticated {
		// Original logic: Always initiate authentication if not authenticated
		t.logger.Debug("User not authenticated, initiating OIDC flow")
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return // Stop processing
	}

	if needsRefresh {
		refreshed := t.refreshToken(rw, req, session)
		if !refreshed {
			t.logger.Infof("Token refresh failed") // Changed from Warn to Infof
			// Check if the client prefers JSON (likely an API call)
			acceptHeader := req.Header.Get("Accept")
			if strings.Contains(acceptHeader, "application/json") {
				t.logger.Debug("Client accepts JSON, sending 401 Unauthorized on refresh failure")
				rw.Header().Set("Content-Type", "application/json")
				rw.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(rw).Encode(map[string]string{"error": "unauthorized", "message": "Token refresh failed"})
			} else {
				// Client likely a browser, initiate full re-authentication
				t.logger.Debug("Client does not prefer JSON, handling refresh failure as expired token (initiating re-auth)")
				t.handleExpiredToken(rw, req, session, redirectURL)
			}
			return // Stop processing
		}
	}

	// Process authenticated request
	email := session.GetEmail()
	if email == "" {
		t.logger.Debug("No email found in session")
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	if !t.isAllowedDomain(email) {
		t.logger.Infof("User with email %s is not from an allowed domain", email)
		errorMsg := fmt.Sprintf("Access denied: Your email domain is not allowed. To log out, visit: %s", t.logoutURLPath)
		t.sendErrorResponse(rw, req, errorMsg, http.StatusForbidden)
		return
	}

	groups, roles, err := t.extractGroupsAndRoles(session.GetAccessToken())
	if err != nil {
		t.logger.Errorf("Failed to extract groups and roles: %v", err)
	} else {
		if len(groups) > 0 {
			req.Header.Set("X-User-Groups", strings.Join(groups, ","))
		}
		if len(roles) > 0 {
			req.Header.Set("X-User-Roles", strings.Join(roles, ","))
		}
	}

	// Check allowed roles and groups
	if len(t.allowedRolesAndGroups) > 0 {
		allowed := false
		for _, roleOrGroup := range append(groups, roles...) {
			if _, ok := t.allowedRolesAndGroups[roleOrGroup]; ok {
				allowed = true
				break
			}
		}
		if !allowed {
			t.logger.Infof("User with email %s does not have any allowed roles or groups", email)
			errorMsg := fmt.Sprintf("Access denied: You do not have any of the allowed roles or groups. To log out, visit: %s", t.logoutURLPath)
			t.sendErrorResponse(rw, req, errorMsg, http.StatusForbidden)
			return
		}
	}

	// Set user information in headers
	req.Header.Set("X-Forwarded-User", email)

	// Set OIDC-specific headers
	req.Header.Set("X-Auth-Request-Redirect", req.URL.RequestURI())
	req.Header.Set("X-Auth-Request-User", email)
	if idToken := session.GetAccessToken(); idToken != "" {
		req.Header.Set("X-Auth-Request-Token", idToken)
	}

	// Set security headers
	rw.Header().Set("X-Frame-Options", "DENY")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("X-XSS-Protection", "1; mode=block")
	rw.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// Set CORS headers
	origin := req.Header.Get("Origin")
	if origin != "" {
		rw.Header().Set("Access-Control-Allow-Origin", origin)
		rw.Header().Set("Access-Control-Allow-Credentials", "true")
		rw.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		rw.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		// Handle preflight requests
		if req.Method == "OPTIONS" {
			rw.WriteHeader(http.StatusOK)
			return
		}
	}

	// Process the request
	t.next.ServeHTTP(rw, req)
}

// handleExpiredToken manages token expiration by clearing the session
// and initiating a new authentication flow.
func (t *TraefikOidc) handleExpiredToken(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	// Clear authentication data but preserve CSRF state
	session.SetAuthenticated(false)
	session.SetAccessToken("")
	session.SetRefreshToken("")
	session.SetEmail("")

	// Save the cleared session state
	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save cleared session: %v", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	t.defaultInitiateAuthentication(rw, req, session, redirectURL)
}

// handleCallback processes the authentication callback from the OIDC provider.
// It validates the callback parameters, exchanges the authorization code for
// tokens, verifies the tokens, and establishes the user's session.
func (t *TraefikOidc) handleCallback(rw http.ResponseWriter, req *http.Request, redirectURL string) {
	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Session error: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Handling callback, URL: %s", req.URL.String())

	// Check for errors in the callback
	if req.URL.Query().Get("error") != "" {
		errorDescription := req.URL.Query().Get("error_description")
		if errorDescription == "" {
			errorDescription = req.URL.Query().Get("error") // Use error code if description is empty
		}
		t.logger.Errorf("Authentication error from provider: %s - %s", req.URL.Query().Get("error"), errorDescription)
		t.sendErrorResponse(rw, req, fmt.Sprintf("Authentication error from provider: %s", errorDescription), http.StatusBadRequest)
		return
	}

	// Validate CSRF state
	state := req.URL.Query().Get("state")
	if state == "" {
		t.logger.Error("No state in callback")
		t.sendErrorResponse(rw, req, "State parameter missing in callback", http.StatusBadRequest)
		return
	}

	csrfToken := session.GetCSRF()
	if csrfToken == "" {
		t.logger.Error("CSRF token missing in session")
		t.sendErrorResponse(rw, req, "CSRF token missing", http.StatusBadRequest)
		return
	}

	if state != csrfToken {
		t.logger.Error("State parameter does not match CSRF token in session")
		t.sendErrorResponse(rw, req, "Invalid state parameter (CSRF mismatch)", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	code := req.URL.Query().Get("code")
	if code == "" {
		t.logger.Error("No code in callback")
		t.sendErrorResponse(rw, req, "No authorization code received in callback", http.StatusBadRequest)
		return
	}

	// Get the code verifier from the session for PKCE flow
	codeVerifier := session.GetCodeVerifier()

	tokenResponse, err := t.tokenExchanger.ExchangeCodeForToken(req.Context(), "authorization_code", code, redirectURL, codeVerifier)
	if err != nil {
		t.logger.Errorf("Failed to exchange code for token: %v", err)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not exchange code for token", http.StatusInternalServerError)
		return
	}

	// Verify tokens and claims
	// Use the exported VerifyToken method now that handleCallback is in main.go
	if err := t.VerifyToken(tokenResponse.IDToken); err != nil {
		t.logger.Errorf("Failed to verify id_token: %v", err)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not verify ID token", http.StatusInternalServerError)
		return
	}

	claims, err := t.extractClaimsFunc(tokenResponse.IDToken)
	if err != nil {
		t.logger.Errorf("Failed to extract claims: %v", err)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not extract claims from token", http.StatusInternalServerError)
		return
	}

	// Verify nonce to prevent replay attacks
	nonceClaim, ok := claims["nonce"].(string)
	if !ok || nonceClaim == "" {
		t.logger.Error("Nonce claim missing in id_token")
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce missing in token", http.StatusInternalServerError)
		return
	}

	sessionNonce := session.GetNonce()
	if sessionNonce == "" {
		t.logger.Error("Nonce not found in session")
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce missing in session", http.StatusInternalServerError)
		return
	}

	if nonceClaim != sessionNonce {
		t.logger.Error("Nonce claim does not match session nonce")
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce mismatch", http.StatusInternalServerError)
		return
	}

	// Validate user's email domain
	// Use the unexported isAllowedDomain method now that handleCallback is in main.go
	email, _ := claims["email"].(string)
	if email == "" || !t.isAllowedDomain(email) {
		t.logger.Errorf("Invalid or disallowed email: %s", email)
		t.sendErrorResponse(rw, req, "Authentication failed: Invalid or disallowed email", http.StatusForbidden)
		return
	}

	// Update session with authentication data
	session.SetAuthenticated(true)
	session.SetEmail(email)
	session.SetAccessToken(tokenResponse.IDToken)
	session.SetRefreshToken(tokenResponse.RefreshToken)

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// Redirect to original path or root
	redirectPath := "/"
	if incomingPath := session.GetIncomingPath(); incomingPath != "" && incomingPath != t.redirURLPath {
		redirectPath = incomingPath
	}

	http.Redirect(rw, req, redirectPath, http.StatusFound)
}

// determineExcludedURL checks if the current request URL is in the excluded list
func (t *TraefikOidc) determineExcludedURL(currentRequest string) bool {
	for excludedURL := range t.excludedURLs {
		if strings.HasPrefix(currentRequest, excludedURL) {
			t.logger.Debugf("URL is excluded - got %s / excluded hit: %s", currentRequest, excludedURL)
			return true
		}
	}
	t.logger.Debugf("URL is not excluded - got %s", currentRequest)
	return false
}

// determineScheme determines the scheme (http or https) of the request
func (t *TraefikOidc) determineScheme(req *http.Request) string {
	if scheme := req.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

// determineHost determines the host of the request
func (t *TraefikOidc) determineHost(req *http.Request) string {
	if host := req.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return req.Host
}

// isUserAuthenticated checks if the user is authenticated by validating their session and token.
// It performs a comprehensive check of the authentication state including:
// 1. Verifying the session's authenticated flag
// 2. Checking for the presence of an access token
// 3. Validating the token's signature and claims
// 4. Checking the token's expiration time
//
// Returns three boolean values:
//   - authenticated: Whether the user is currently authenticated
//   - needsRefresh: Whether the token is valid but will expire soon (within grace period)
//   - expired: Whether the token has expired or is otherwise invalid
func (t *TraefikOidc) isUserAuthenticated(session *SessionData) (bool, bool, bool) {
	if !session.GetAuthenticated() {
		t.logger.Debug("User is not authenticated according to session")
		return false, false, false
	}

	accessToken := session.GetAccessToken()
	if accessToken == "" {
		t.logger.Debug("No access token found in session")
		return false, false, true // Session is invalid, consider it expired
	}

	// Verify the token structure and signature first
	jwt, err := parseJWT(accessToken)
	if err != nil {
		t.logger.Errorf("Failed to parse JWT during auth check: %v", err)
		return false, false, true // Invalid format, treat as expired/invalid
	}
	if err := t.VerifyJWTSignatureAndClaims(jwt, accessToken); err != nil {
		// Check if the error is specifically about expiration
		if strings.Contains(err.Error(), "token has expired") {
			t.logger.Debugf("Token signature/claims valid but token expired, attempting refresh")
			// Token is expired but otherwise valid, signal for refresh
			return true, true, false // Authenticated=true (was valid), NeedsRefresh=true, Expired=false (because refresh is possible)
		}
		// Other verification error (signature, issuer, audience etc.)
		t.logger.Errorf("Token verification failed (non-expiration): %v", err)
		return false, false, true // Token is invalid for other reasons
	}

	// Claims already parsed within VerifyJWTSignatureAndClaims if it didn't error early
	claims := jwt.Claims

	expClaim, ok := claims["exp"].(float64)
	if !ok {
		t.logger.Error("Failed to get expiration time from claims")
		return false, false, true
	}

	expTime := int64(expClaim)

	// Expiration check is now handled within VerifyJWTSignatureAndClaims logic above
	// We only get here if the token is valid and not expired

	// Check if token is nearing expiration (needs refresh proactively)
	// Check if token is nearing expiration using the configured grace period
	if time.Unix(expTime, 0).Before(time.Now().Add(t.refreshGracePeriod)) {
		// Recalculate remaining seconds for logging clarity if needed, using the configured duration
		remainingSeconds := int64(time.Until(time.Unix(expTime, 0)).Seconds())
		t.logger.Debugf("Token nearing expiration (expires in %d seconds, grace period %s), scheduling refresh", remainingSeconds, t.refreshGracePeriod)
		return true, true, false // Needs proactive refresh
	}

	// Token is valid, not expired, and not nearing expiration
	return true, false, false
}

// defaultInitiateAuthentication initiates the OIDC authentication process.
// This function prepares and starts a new authentication flow by:
// 1. Generating security tokens (CSRF token and nonce) to prevent attacks
// 2. Clearing any existing session data to avoid state conflicts
// 3. Storing the original request path to redirect back after authentication
// 4. Building the authorization URL with all required OIDC parameters
// 5. Redirecting the user to the OIDC provider's authorization endpoint
//
// Parameters:
//   - rw: The HTTP response writer for sending the redirect
//   - req: The original HTTP request that triggered authentication
//   - session: The user's session data for storing authentication state
//   - redirectURL: The callback URL where the OIDC provider will redirect after authentication
func (t *TraefikOidc) defaultInitiateAuthentication(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	// Generate CSRF token and nonce
	csrfToken := uuid.NewString()
	nonce, err := generateNonce()
	if err != nil {
		http.Error(rw, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Generate PKCE code verifier and challenge if PKCE is enabled
	var codeVerifier, codeChallenge string
	if t.enablePKCE {
		var err error
		codeVerifier, err = generateCodeVerifier()
		if err != nil {
			http.Error(rw, "Failed to generate code verifier", http.StatusInternalServerError)
			return
		}

		// Derive code challenge from verifier
		codeChallenge = deriveCodeChallenge(codeVerifier)
	}

	// Clear any existing session data to avoid stale state causing redirect loops
	session.Clear(req, rw)

	// Set new session values
	session.SetCSRF(csrfToken)
	session.SetNonce(nonce)

	// Only set code verifier if PKCE is enabled
	if t.enablePKCE {
		session.SetCodeVerifier(codeVerifier)
	}

	session.SetIncomingPath(req.URL.RequestURI())

	// Save the session
	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// Build and redirect to authentication URL
	authURL := t.buildAuthURL(redirectURL, csrfToken, nonce, codeChallenge)
	http.Redirect(rw, req, authURL, http.StatusFound)
}

// verifyToken verifies the token using the token verifier interface.
// This function delegates to the configured token verifier implementation,
// which by default is the TraefikOidc instance itself (implementing the VerifyToken method).
// This design allows for easy mocking in tests and potential future extension.
func (t *TraefikOidc) verifyToken(token string) error {
	return t.tokenVerifier.VerifyToken(token)
}

// buildAuthURL constructs the authentication URL with optional PKCE support
func (t *TraefikOidc) buildAuthURL(redirectURL, state, nonce, codeChallenge string) string {
	params := url.Values{}
	params.Set("client_id", t.clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURL)
	params.Set("state", state)
	params.Set("nonce", nonce)

	// Add PKCE parameters only if PKCE is enabled and we have a code challenge
	if t.enablePKCE && codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	if len(t.scopes) > 0 {
		params.Set("scope", strings.Join(t.scopes, " "))
	}

	return t.buildURLWithParams(t.authURL, params)
}

// buildURLWithParams ensures a URL is absolute and appends query parameters
func (t *TraefikOidc) buildURLWithParams(baseURL string, params url.Values) string {
	// Ensure URL is absolute
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		// Extract issuer base URL
		issuerURL, err := url.Parse(t.issuerURL)
		if err == nil {
			return fmt.Sprintf("%s://%s%s?%s",
				issuerURL.Scheme,
				issuerURL.Host,
				baseURL,
				params.Encode())
		}
	}
	return baseURL + "?" + params.Encode()
}

// startTokenCleanup starts the token cleanup goroutine
func (t *TraefikOidc) startTokenCleanup() {
	ticker := time.NewTicker(1 * time.Minute) // Run cleanup every minute
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			t.logger.Debug("Starting token cleanup cycle")
			t.tokenCache.Cleanup()
			// t.tokenBlacklist.Cleanup() // Removed: Generic Cache handles its own cleanup
			t.jwkCache.Cleanup() // Assuming jwkCache is the cache from cache.go
			// Removed runtime.GC() call
		}
	}()
}

// RevokeToken adds the token to the blacklist
func (t *TraefikOidc) RevokeToken(token string) {
	// Remove from cache
	t.tokenCache.Delete(token)

	// Add to blacklist with default expiration
	expiry := time.Now().Add(24 * time.Hour) // or other appropriate duration
	// Use Set with a duration. Value 'true' is arbitrary, we only care about existence.
	t.tokenBlacklist.Set(token, true, time.Until(expiry))
}

// RevokeTokenWithProvider revokes the token with the provider
func (t *TraefikOidc) RevokeTokenWithProvider(token, tokenType string) error {
	t.logger.Debugf("Revoking token with provider")

	data := url.Values{
		"token":           {token},
		"token_type_hint": {tokenType},
		"client_id":       {t.clientID},
		"client_secret":   {t.clientSecret},
	}

	// Create the request
	req, err := http.NewRequestWithContext(context.Background(), "POST", t.revocationURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token revocation request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send token revocation request: %w", err)
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token revocation failed with status %d: %s", resp.StatusCode, string(body))
	}

	t.logger.Debugf("Token successfully revoked")
	return nil
}

// refreshToken refreshes the user's token, protected by a mutex within the session.
func (t *TraefikOidc) refreshToken(rw http.ResponseWriter, req *http.Request, session *SessionData) bool {
	// Lock the mutex specific to this session instance before attempting refresh
	session.refreshMutex.Lock()
	defer session.refreshMutex.Unlock()

	t.logger.Debug("Attempting to refresh token (mutex acquired)")
	refreshToken := session.GetRefreshToken() // Get token *after* acquiring lock
	if refreshToken == "" {
		t.logger.Debug("No refresh token found in session (inside lock)")
		return false
	}

	newToken, err := t.tokenExchanger.GetNewTokenWithRefreshToken(refreshToken)
	if err != nil {
		// Log the error, potentially clear the invalid refresh token?
		t.logger.Errorf("Failed to refresh token using refresh token: %v", err)
		// Consider clearing the refresh token from the session here if the error indicates it's invalid
		// session.SetRefreshToken("") // Example: Clear potentially invalid token
		// session.Save(req, rw) // Need to handle potential save error
		return false
	}

	// Verify the new access token
	if err := t.verifyToken(newToken.IDToken); err != nil {
		t.logger.Errorf("Failed to verify new access token: %v", err)
		return false
	}

	// Update session with new tokens
	session.SetAccessToken(newToken.IDToken)
	session.SetRefreshToken(newToken.RefreshToken)

	// Save the session
	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save refreshed session: %v", err)
		return false
	}

	return true
}

// isAllowedDomain checks if the user's email domain is allowed
func (t *TraefikOidc) isAllowedDomain(email string) bool {
	if len(t.allowedUserDomains) == 0 {
		return true // If no domains are specified, all are allowed
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false // Invalid email format
	}

	domain := parts[1]
	_, ok := t.allowedUserDomains[domain]
	return ok
}

// extractGroupsAndRoles extracts groups and roles from the id_token
func (t *TraefikOidc) extractGroupsAndRoles(idToken string) ([]string, []string, error) {
	claims, err := t.extractClaimsFunc(idToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	var groups []string
	var roles []string

	// Extract groups with type checking
	if groupsClaim, exists := claims["groups"]; exists {
		groupsSlice, ok := groupsClaim.([]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("groups claim is not an array")
		}
		for _, group := range groupsSlice {
			if groupStr, ok := group.(string); ok {
				t.logger.Debugf("Found group: %s", groupStr)
				groups = append(groups, groupStr)
			}
		}
	}

	// Extract roles with type checking
	if rolesClaim, exists := claims["roles"]; exists {
		rolesSlice, ok := rolesClaim.([]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("roles claim is not an array")
		}
		for _, role := range rolesSlice {
			if roleStr, ok := role.(string); ok {
				t.logger.Debugf("Found role: %s", roleStr)
				roles = append(roles, roleStr)
			}
		}
	}

	return groups, roles, nil
}

// buildFullURL constructs a full URL from scheme, host and path
func buildFullURL(scheme, host, path string) string {
	// If the path is already a full URL, return it as-is
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	// Ensure the path starts with a forward slash
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

// --- TokenExchanger Interface Implementation ---

// ExchangeCodeForToken implements the TokenExchanger interface.
// It calls the existing exchangeTokens helper function.
func (t *TraefikOidc) ExchangeCodeForToken(ctx context.Context, grantType string, codeOrToken string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
	// Note: The original exchangeTokens helper is defined in helpers.go and is already a method on *TraefikOidc
	return t.exchangeTokens(ctx, grantType, codeOrToken, redirectURL, codeVerifier)
}

// GetNewTokenWithRefreshToken implements the TokenExchanger interface.
// It calls the existing getNewTokenWithRefreshToken helper function.
func (t *TraefikOidc) GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	// Note: The original getNewTokenWithRefreshToken helper is defined in helpers.go and is already a method on *TraefikOidc
	return t.getNewTokenWithRefreshToken(refreshToken)
}

// sendErrorResponse sends an error response, adapting to the client's Accept header.
func (t *TraefikOidc) sendErrorResponse(rw http.ResponseWriter, req *http.Request, message string, code int) {
	acceptHeader := req.Header.Get("Accept")

	// Check if the client prefers JSON
	if strings.Contains(acceptHeader, "application/json") {
		t.logger.Debugf("Sending JSON error response (code %d): %s", code, message)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(code)
		// Use a simple error structure
		json.NewEncoder(rw).Encode(map[string]interface{}{
			"error":             http.StatusText(code),
			"error_description": message,
			"status_code":       code,
		})
		return
	}

	// Default to HTML response for browsers
	t.logger.Debugf("Sending HTML error response (code %d): %s", code, message)

	// Determine the return URL (mostly relevant for HTML)
	returnURL := "/"                                 // Default to root
	session, err := t.sessionManager.GetSession(req) // Attempt to get session for return URL
	if err == nil {
		incomingPath := session.GetIncomingPath()
		// Use incoming path if it's valid and not one of the special OIDC paths
		if incomingPath != "" && incomingPath != t.redirURLPath && incomingPath != t.logoutURLPath {
			returnURL = incomingPath
		}
	} else {
		t.logger.Infof("Could not get session to determine return URL in sendErrorResponse: %v", err)
	}

	// Basic HTML structure for the error page
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Error</title>
    <style>
        body { font-family: sans-serif; padding: 20px; background-color: #f8f9fa; color: #343a40; }
        h1 { color: #dc3545; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .container { max-width: 600px; margin: auto; background: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authentication Error</h1>
        <p>%s</p>
        <p><a href="%s">Return to application</a></p>
    </div>
</body>
</html>`, message, returnURL)

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(code)
	_, _ = rw.Write([]byte(htmlBody)) // Ignore write error as header is already sent
}
