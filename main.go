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
	"strings"
	"time"

	"runtime"

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

const ConstSessionTimeout = 86400 // Session timeout in seconds

// TokenVerifier interface for token verification
type TokenVerifier interface {
	VerifyToken(token string) error
}

// JWTVerifier interface for JWT verification
type JWTVerifier interface {
	VerifyJWTSignatureAndClaims(jwt *JWT, token string) error
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
	tokenBlacklist             *TokenBlacklist
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
	exchangeCodeForTokenFunc   func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error)
	extractClaimsFunc          func(tokenString string) (map[string]interface{}, error)
	initComplete               chan struct{}
	endSessionURL              string
	postLogoutRedirectURI      string
	sessionManager             *SessionManager
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

	return nil
}

// performPreVerificationChecks performs rate limiting and blacklist checks
func (t *TraefikOidc) performPreVerificationChecks(token string) error {
	// Enforce rate limiting
	if !t.limiter.Allow() {
		return fmt.Errorf("rate limit exceeded")
	}

	// Check if token is blacklisted
	if t.tokenBlacklist.IsBlacklisted(token) {
		return fmt.Errorf("token is blacklisted")
	}

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
		tokenBlacklist:        NewTokenBlacklist(),
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
	}

	t.sessionManager, _ = NewSessionManager(config.SessionEncryptionKey, config.ForceHTTPS, t.logger)
	t.extractClaimsFunc = extractClaims
	t.exchangeCodeForTokenFunc = t.exchangeCodeForToken
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
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	if needsRefresh {
		refreshed := t.refreshToken(rw, req, session)
		if !refreshed {
			t.handleExpiredToken(rw, req, session, redirectURL)
			return
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
		http.Error(rw, fmt.Sprintf("Access denied: Your email domain is not allowed. To log out, visit: %s", t.logoutURLPath), http.StatusForbidden)
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
			http.Error(rw, fmt.Sprintf("Access denied: You do not have any of the allowed roles or groups. To log out, visit: %s", t.logoutURLPath), http.StatusForbidden)
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

	// Verify the token
	if err := t.verifyToken(accessToken); err != nil {
		t.logger.Errorf("Token verification failed: %v", err)
		return false, false, true // Token is invalid, consider it expired
	}

	claims, err := extractClaims(accessToken)
	if err != nil {
		t.logger.Errorf("Failed to extract claims: %v", err)
		return false, false, true
	}

	expClaim, ok := claims["exp"].(float64)
	if !ok {
		t.logger.Error("Failed to get expiration time from claims")
		return false, false, true
	}

	now := time.Now().Unix()
	expTime := int64(expClaim)

	if now > expTime {
		t.logger.Debug("Token has expired")
		return false, false, true
	}

	gracePeriod := time.Minute * 5
	if now+int64(gracePeriod.Seconds()) > expTime {
		t.logger.Debug("Token will expire soon")
		return true, true, false // Token will expire soon, needs refresh
	}

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
			t.tokenBlacklist.Cleanup()
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
	t.tokenBlacklist.Add(token, expiry)
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

// refreshToken refreshes the user's token
func (t *TraefikOidc) refreshToken(rw http.ResponseWriter, req *http.Request, session *SessionData) bool {
	t.logger.Debug("Refreshing token")
	refreshToken := session.GetRefreshToken()
	if refreshToken == "" {
		t.logger.Debug("No refresh token found in session")
		return false
	}

	newToken, err := t.getNewTokenWithRefreshToken(refreshToken)
	if err != nil {
		t.logger.Errorf("Failed to refresh token: %v", err)
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
