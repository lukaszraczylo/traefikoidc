package traefikoidc

import (
	"bytes"
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
	"text/template"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// createDefaultHTTPClient creates a new http.Client with settings optimized for OIDC communication.
// It configures the transport with specific timeouts (dial, keepalive, TLS handshake, idle connection),
// connection limits (max idle, max per host), enables HTTP/2, and sets a default request timeout.
// It also configures redirect handling to follow redirects up to a limit.
//
// Returns:
//   - A pointer to the configured http.Client.
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
	includedURLs               map[string]struct{}
	allowedUserDomains         map[string]struct{}
	allowedRolesAndGroups      map[string]struct{}
	initiateAuthenticationFunc func(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string)
	// exchangeCodeForTokenFunc   func(code string, redirectURL string, codeVerifier string) (*TokenResponse, error) // Replaced by interface
	extractClaimsFunc     func(tokenString string) (map[string]interface{}, error)
	initComplete          chan struct{}
	endSessionURL         string
	postLogoutRedirectURI string
	sessionManager        *SessionManager
	tokenExchanger        TokenExchanger                // Added field for mocking
	refreshGracePeriod    time.Duration                 // Configurable grace period for proactive refresh
	headerTemplates       map[string]*template.Template // Parsed templates for custom headers
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

// VerifyToken implements the TokenVerifier interface. It performs a comprehensive validation of an ID token:
// 1. Checks the token cache; returns nil immediately if a valid cached entry exists.
// 2. Performs pre-verification checks (rate limiting, blacklist).
// 3. Parses the raw token string into a JWT struct.
// 4. Verifies the JWT signature and standard claims (iss, aud, exp, iat, nbf, sub) using VerifyJWTSignatureAndClaims.
// 5. If verification succeeds, caches the token claims until the token's expiration time.
// 6. If verification succeeds and the token has a JTI claim, adds the JTI to the blacklist cache to prevent replay attacks.
//
// Parameters:
//   - token: The raw ID token string to verify.
//
// Returns:
//   - nil if the token is valid according to all checks.
//   - An error describing the reason for validation failure (e.g., rate limit, blacklisted, parsing error, signature error, claim error).
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

// performPreVerificationChecks executes preliminary checks before attempting full token validation.
// It enforces rate limiting using the configured limiter and checks if the raw token string
// or its JTI (if extractable) exists in the blacklist cache.
//
// Parameters:
//   - token: The raw token string being verified.
//
// Returns:
//   - nil if all pre-verification checks pass.
//   - An error if the rate limit is exceeded or the token/JTI is blacklisted.
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

// cacheVerifiedToken adds the claims of a successfully verified token to the token cache.
// It calculates the remaining duration until the token's 'exp' claim and uses that
// duration for the cache entry's lifetime.
//
// Parameters:
//   - token: The raw token string (used as the cache key).
//   - claims: The map of claims extracted from the verified token.
func (t *TraefikOidc) cacheVerifiedToken(token string, claims map[string]interface{}) {
	expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
	now := time.Now()
	duration := expirationTime.Sub(now)
	t.tokenCache.Set(token, claims, duration)
}

// VerifyJWTSignatureAndClaims implements the JWTVerifier interface. It verifies the signature
// of a parsed JWT against the provider's public keys obtained from the JWKS endpoint,
// and then validates the standard JWT claims (iss, aud, exp, iat, nbf, sub, jti replay).
//
// Parameters:
//   - jwt: A pointer to the parsed JWT struct containing header and claims.
//   - token: The original raw token string (used for signature verification).
//
// Returns:
//   - nil if both the signature and all standard claims are valid.
//   - An error describing the validation failure (e.g., failed to get JWKS, missing kid/alg,
//     no matching key, signature verification failed, standard claim validation failed).
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

// New is the constructor for the TraefikOidc middleware plugin.
// It is called by Traefik during plugin initialization. It performs the following steps:
//  1. Creates a default configuration if none is provided.
//  2. Validates the session encryption key length.
//  3. Initializes the logger based on the configured log level.
//  4. Sets up the HTTP client (using defaults if none provided in config).
//  5. Creates the main TraefikOidc struct, populating fields from the config
//     (paths, client details, PKCE/HTTPS flags, scopes, rate limiter, caches, allowed lists).
//  6. Initializes the SessionManager.
//  7. Sets up internal function pointers/interfaces (extractClaimsFunc, initiateAuthenticationFunc, tokenVerifier, jwtVerifier, tokenExchanger).
//  8. Adds default excluded URLs.
//  9. Starts background goroutines for token cache cleanup and OIDC provider metadata initialization/refresh.
//
// Parameters:
//   - ctx: The context provided by Traefik for initialization.
//   - next: The next http.Handler in the Traefik middleware chain.
//   - config: The plugin configuration provided by the user in Traefik static/dynamic configuration.
//   - name: The name assigned to this middleware instance by Traefik.
//
// Returns:
//   - An http.Handler (the TraefikOidc instance itself, which implements ServeHTTP).
//   - An error if essential configuration is missing or invalid (e.g., short encryption key).
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
		includedURLs:          createStringMap(config.IncludedURLs),
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
	if len(t.includedURLs) <= 0 {
		for k, v := range defaultExcludedURLs {
			t.excludedURLs[k] = v
		}
	}

	t.tokenVerifier = t
	t.jwtVerifier = t
	t.startTokenCleanup()
	t.tokenExchanger = t // Initialize the interface field to self

	// Initialize and parse header templates
	t.headerTemplates = make(map[string]*template.Template)
	for _, header := range config.Headers {
		tmpl, err := template.New(header.Name).Parse(header.Value)
		if err != nil {
			logger.Errorf("Failed to parse header template for %s: %v", header.Name, err)
			continue
		}
		t.headerTemplates[header.Name] = tmpl
		logger.Debugf("Parsed template for header %s: %s", header.Name, header.Value)
	}

	go t.initializeMetadata(config.ProviderURL)

	return t, nil
}

// initializeMetadata asynchronously fetches and caches the OIDC provider metadata.
// It uses the MetadataCache to retrieve potentially cached data or fetch fresh data
// via discoverProviderMetadata. On successful retrieval, it updates the middleware's
// endpoint URLs (auth, token, jwks, etc.), starts the periodic metadata refresh goroutine,
// and signals completion by closing the initComplete channel. If fetching fails initially,
// it logs an error and the middleware might remain uninitialized until a successful refresh.
//
// Parameters:
//   - providerURL: The base URL of the OIDC provider.
func (t *TraefikOidc) initializeMetadata(providerURL string) {
	t.logger.Debug("Starting provider metadata discovery")

	// Get metadata from cache or fetch it
	metadata, err := t.metadataCache.GetMetadata(providerURL, t.httpClient, t.logger)
	if err != nil {
		t.logger.Errorf("Failed to get provider metadata: %v", err)
		// Consider retrying or handling this more gracefully
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

	t.logger.Error("Received nil metadata during initialization")
	// Consider what should happen if metadata is nil after GetMetadata returns no error
}

// updateMetadataEndpoints updates the relevant endpoint URL fields (jwksURL, authURL, tokenURL, etc.)
// within the TraefikOidc instance based on the discovered provider metadata.
// This is called after successfully fetching or refreshing the metadata.
//
// Parameters:
//   - metadata: A pointer to the ProviderMetadata struct containing the discovered endpoints.
func (t *TraefikOidc) updateMetadataEndpoints(metadata *ProviderMetadata) {
	t.jwksURL = metadata.JWKSURL
	t.authURL = metadata.AuthURL
	t.tokenURL = metadata.TokenURL
	t.issuerURL = metadata.Issuer
	t.revocationURL = metadata.RevokeURL
	t.endSessionURL = metadata.EndSessionURL
}

// startMetadataRefresh starts a background goroutine that periodically attempts to refresh
// the OIDC provider metadata by calling GetMetadata on the metadataCache.
// It runs on a fixed ticker (currently 1 hour). Successful refreshes update the
// middleware's endpoint URLs via updateMetadataEndpoints. Fetch errors are logged.
//
// Parameters:
//   - providerURL: The base URL of the OIDC provider, used for subsequent refresh attempts.
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
		} else {
			t.logger.Error("Received nil metadata during refresh")
		}
	}
}

// discoverProviderMetadata attempts to fetch the OIDC provider's configuration from its
// well-known discovery endpoint (".well-known/openid-configuration").
// It implements an exponential backoff retry mechanism in case of transient network errors
// or provider unavailability during startup.
//
// Parameters:
//   - providerURL: The base URL of the OIDC provider.
//   - httpClient: The HTTP client to use for the request.
//   - l: The logger instance for recording retries and errors.
//
// Returns:
//   - A pointer to the fetched ProviderMetadata struct.
//   - An error if fetching fails after all retries or if a timeout is exceeded.
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
		l.Debugf("Failed to fetch provider metadata (attempt %d/%d), retrying in %s. Error: %v", attempt+1, maxRetries, delay, err)
		time.Sleep(delay)
	}

	l.Errorf("Max retries exceeded while fetching provider metadata")
	return nil, fmt.Errorf("max retries exceeded while fetching provider metadata: %w", lastErr)
}

// fetchMetadata performs a single attempt to fetch and decode the OIDC provider metadata
// from the specified well-known configuration URL.
//
// Parameters:
//   - wellKnownURL: The full URL to the ".well-known/openid-configuration" endpoint.
//   - httpClient: The HTTP client to use for the GET request.
//
// Returns:
//   - A pointer to the decoded ProviderMetadata struct.
//   - An error if the GET request fails, the status code is not 200 OK, or JSON decoding fails.
func fetchMetadata(wellKnownURL string, httpClient *http.Client) (*ProviderMetadata, error) {
	resp, err := httpClient.Get(wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch provider metadata: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("received nil response from provider at %s", wellKnownURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch provider metadata from %s: status code %d, body: %s", wellKnownURL, resp.StatusCode, string(bodyBytes))
	}

	var metadata ProviderMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		// Attempt to read body for better error context if decoding fails
		// Note: resp.Body might be partially read by Decode, so read remaining
		bodyBytes, readErr := io.ReadAll(io.MultiReader(json.NewDecoder(resp.Body).Buffered(), resp.Body))
		if readErr != nil {
			bodyBytes = []byte(fmt.Sprintf("(failed to read response body: %v)", readErr))
		}
		return nil, fmt.Errorf("failed to decode provider metadata from %s: %w. Response body: %s", wellKnownURL, err, string(bodyBytes))
	}

	return &metadata, nil
}

// ServeHTTP is the main entry point for incoming requests to the middleware.
// It orchestrates the OIDC authentication flow.
func (t *TraefikOidc) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// --- Initialization Check ---
	select {
	case <-t.initComplete:
		if t.issuerURL == "" { // Check if initialization actually succeeded
			t.logger.Error("OIDC provider metadata initialization failed or incomplete")
			http.Error(rw, "OIDC provider metadata initialization failed - please check provider availability and configuration", http.StatusServiceUnavailable)
			return
		}
	case <-req.Context().Done():
		t.logger.Debug("Request cancelled while waiting for OIDC initialization")
		http.Error(rw, "Request cancelled", http.StatusRequestTimeout) // 408 might be more appropriate
		return
	case <-time.After(30 * time.Second): // Timeout for initialization
		t.logger.Error("Timeout waiting for OIDC initialization")
		http.Error(rw, "Timeout waiting for OIDC provider initialization - please try again later", http.StatusServiceUnavailable)
		return
	}

	if len(t.excludedURLs) > 0 && len(t.includedURLs) > 0 {
		t.logger.Error("Only one of excludedURLs or includedURLs should be set")
		http.Error(rw, "Only one of excludedURLs or includedURLs should be set", http.StatusInternalServerError)
		return
	}
	// --- Excluded Paths Check ---
	if len(t.excludedURLs) > 0 && t.determineExcludedURL(req.URL.Path) {
		t.logger.Debugf("Request path %s excluded by configuration, bypassing OIDC", req.URL.Path)
		t.next.ServeHTTP(rw, req)
		return
	}
	// --- Included Paths Check ---
	if len(t.includedURLs) > 0 && !t.determineIncludedURL(req.URL.Path) {
		t.logger.Debugf("Request path %s not included by configuration, bypassing OIDC", req.URL.Path)
		t.next.ServeHTTP(rw, req)
		return
	}
	// --- SSE Check ---
	acceptHeader := req.Header.Get("Accept")
	if strings.Contains(acceptHeader, "text/event-stream") {
		t.logger.Debugf("Request accepts text/event-stream (%s), bypassing OIDC", acceptHeader)
		t.next.ServeHTTP(rw, req)
		return
	}

	// --- Session Retrieval ---
	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		// Log the specific session error
		t.logger.Errorf("Error getting session: %v. Initiating authentication.", err)
		// Attempt to get a new session to store CSRF etc.
		session, _ = t.sessionManager.GetSession(req) // Ignore error here, proceed with new session
		if session != nil {
			// Pass rw to ensure expiring cookies are sent if possible
			if clearErr := session.Clear(req, rw); clearErr != nil {
				t.logger.Errorf("Error clearing potentially corrupted session: %v", clearErr)
			}
		} else {
			// If even getting a new session fails, something is very wrong
			t.logger.Error("Critical session error: Failed to get even a new session.")
			http.Error(rw, "Critical session error", http.StatusInternalServerError)
			return
		}
		scheme := t.determineScheme(req)
		host := t.determineHost(req)
		redirectURL := buildFullURL(scheme, host, t.redirURLPath)
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	// --- URL Handling (Callback, Logout) ---
	scheme := t.determineScheme(req)
	host := t.determineHost(req)
	redirectURL := buildFullURL(scheme, host, t.redirURLPath) // Used for callback and re-auth

	if req.URL.Path == t.logoutURLPath {
		t.handleLogout(rw, req)
		return
	}
	if req.URL.Path == t.redirURLPath {
		t.handleCallback(rw, req, redirectURL)
		return
	}

	// --- Authentication & Refresh Logic ---
	authenticated, needsRefresh, expired := t.isUserAuthenticated(session)

	if expired {
		t.logger.Debug("Session token is definitively expired or invalid, initiating re-auth")
		// handleExpiredToken clears the session and initiates auth
		t.handleExpiredToken(rw, req, session, redirectURL)
		return
	}

	// If authenticated and token doesn't need proactive refresh, proceed directly
	if authenticated && !needsRefresh {
		t.logger.Debug("User authenticated and token valid, proceeding to process authorized request")
		t.processAuthorizedRequest(rw, req, session, redirectURL)
		return
	}

	// --- Attempt Refresh if Needed or Possible ---
	// Conditions to attempt refresh:
	// 1. Token needs proactive refresh (authenticated=true, needsRefresh=true)
	// 2. Token is invalid/expired but a refresh token exists (authenticated=false, needsRefresh=true)
	refreshTokenPresent := session.GetRefreshToken() != ""
	shouldAttemptRefresh := needsRefresh && refreshTokenPresent

	if shouldAttemptRefresh {
		if needsRefresh && authenticated {
			t.logger.Debug("Session token needs proactive refresh, attempting refresh")
		} else if needsRefresh && !authenticated {
			t.logger.Debug("Access token invalid/expired, but refresh token found. Attempting refresh.")
		}

		refreshed := t.refreshToken(rw, req, session)
		if refreshed {
			// Refresh succeeded, proceed to authorization checks
			t.logger.Debug("Token refresh successful, proceeding to process authorized request")
			t.processAuthorizedRequest(rw, req, session, redirectURL)
			return
		}

		// Refresh failed
		t.logger.Infof("Token refresh failed (authenticated=%v, needsRefresh=%v, refreshTokenPresent=%v)", authenticated, needsRefresh, refreshTokenPresent)
		// Handle refresh failure (401 for API, re-auth for browser)
		acceptHeader := req.Header.Get("Accept")
		if strings.Contains(acceptHeader, "application/json") {
			t.logger.Debug("Client accepts JSON, sending 401 Unauthorized on refresh failure")
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(rw).Encode(map[string]string{"error": "unauthorized", "message": "Token refresh failed"})
		} else {
			t.logger.Debug("Client does not prefer JSON, handling refresh failure by initiating re-auth")
			// Use defaultInitiateAuthentication which clears the session properly
			t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		}
		return // Stop processing
	}

	// --- Initiate Full Authentication ---
	// If we reach here, it means:
	// - User is not authenticated (!authenticated)
	// - AND EITHER token doesn't need refresh (!needsRefresh, e.g., first visit)
	// - OR refresh token is missing (!refreshTokenPresent)
	// - OR refresh was attempted but failed (handled above)
	t.logger.Debugf("Initiating full OIDC authentication flow (authenticated=%v, needsRefresh=%v, refreshTokenPresent=%v)", authenticated, needsRefresh, refreshTokenPresent)
	t.defaultInitiateAuthentication(rw, req, session, redirectURL)
}

// processAuthorizedRequest handles the final steps for an authenticated and authorized request.
// It performs domain/role/group checks, sets headers, and forwards the request.
func (t *TraefikOidc) processAuthorizedRequest(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	email := session.GetEmail()
	if email == "" {
		t.logger.Error("CRITICAL: No email found in session during final processing, initiating re-auth")
		// This case should ideally not happen if checks are done correctly before calling this,
		// but as a safeguard, initiate re-authentication.
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
		// Continue without group/role headers if extraction fails
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

	// Execute and set templated headers if configured
	if len(t.headerTemplates) > 0 {
		accessToken := session.GetAccessToken()
		refreshToken := session.GetRefreshToken()
		claims, err := t.extractClaimsFunc(accessToken)
		if err != nil {
			t.logger.Errorf("Failed to extract claims for template headers: %v", err)
		} else {
			// Create template data context with available tokens and claims
			// Fields must be exported (uppercase) to be accessible in templates
			templateData := struct {
				// These fields need to be exported (uppercase) for template access
				AccessToken  string
				IdToken      string
				RefreshToken string
				Claims       map[string]interface{}
			}{
				AccessToken:  accessToken,
				IdToken:      accessToken, // Using access token as ID token
				RefreshToken: refreshToken,
				Claims:       claims,
			}

			// Execute each template and set the resulting header
			for headerName, tmpl := range t.headerTemplates {
				var buf bytes.Buffer
				if err := tmpl.Execute(&buf, templateData); err != nil {
					t.logger.Errorf("Failed to execute template for header %s: %v", headerName, err)
					continue
				}
				headerValue := buf.String()
				req.Header.Set(headerName, headerValue)
				t.logger.Debugf("Set templated header %s = %s", headerName, headerValue)
			}
		}
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
	t.logger.Debugf("Request authorized for user %s, forwarding to next handler", email)
	t.next.ServeHTTP(rw, req)
}

// handleExpiredToken is called when a user's session contains an expired token or
// when a token refresh attempt fails for a browser client.
// It clears the authentication-related data (tokens, email, authenticated flag) from the session,
// saves the cleared session, and then initiates a new authentication flow by calling
// defaultInitiateAuthentication, redirecting the user to the OIDC provider.
//
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The HTTP request.
//   - session: The user's session data containing the expired token information.
//   - redirectURL: The callback URL to be used in the new authentication flow.
func (t *TraefikOidc) handleExpiredToken(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	t.logger.Debug("Handling expired token: Clearing session and initiating re-authentication.")
	// Clear authentication data but preserve CSRF state if possible (though Clear might remove it)
	session.SetAuthenticated(false)
	session.SetAccessToken("")
	session.SetRefreshToken("")
	session.SetEmail("")

	// Save the cleared session state (this sends expired cookies)
	// Pass rw to ensure expiring cookies are sent
	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save cleared session during expired token handling: %v", err)
		// Still attempt to initiate authentication, but log the error
	}

	// Initiate a new authentication flow
	t.defaultInitiateAuthentication(rw, req, session, redirectURL)
}

// handleCallback handles the request received at the OIDC callback URL (redirect_uri).
// It performs the following steps:
// 1. Retrieves the user session associated with the callback request.
// 2. Checks for error parameters returned by the OIDC provider.
// 3. Validates the 'state' parameter against the CSRF token stored in the session.
// 4. Extracts the authorization 'code' from the query parameters.
// 5. Retrieves the PKCE 'code_verifier' from the session (if PKCE is enabled).
// 6. Exchanges the authorization code for tokens using the TokenExchanger interface.
// 7. Verifies the received ID token's signature and standard claims using VerifyToken.
// 8. Extracts claims from the verified ID token.
// 9. Verifies the 'nonce' claim against the nonce stored in the session.
// 10. Validates the user's email domain against the allowed list.
// 11. If all checks pass, updates the session with authentication details (status, email, tokens).
// 12. Saves the updated session.
// 13. Redirects the user back to their original requested path (stored in session) or the root path.
// If any step fails, it sends an appropriate error response using sendErrorResponse.
//
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The incoming HTTP request to the callback URL.
//   - redirectURL: The fully qualified callback URL (used in the token exchange request).
func (t *TraefikOidc) handleCallback(rw http.ResponseWriter, req *http.Request, redirectURL string) {
	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Session error during callback: %v", err)
		http.Error(rw, "Session error during callback", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Handling callback, URL: %s", req.URL.String())

	// Check for errors in the callback
	if req.URL.Query().Get("error") != "" {
		errorDescription := req.URL.Query().Get("error_description")
		if errorDescription == "" {
			errorDescription = req.URL.Query().Get("error") // Use error code if description is empty
		}
		t.logger.Errorf("Authentication error from provider during callback: %s - %s", req.URL.Query().Get("error"), errorDescription)
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
		t.logger.Error("CSRF token missing in session during callback")
		t.sendErrorResponse(rw, req, "CSRF token missing in session", http.StatusBadRequest)
		return
	}

	if state != csrfToken {
		t.logger.Error("State parameter does not match CSRF token in session during callback")
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
		t.logger.Errorf("Failed to exchange code for token during callback: %v", err)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not exchange code for token", http.StatusInternalServerError)
		return
	}

	// Verify tokens and claims
	if err := t.VerifyToken(tokenResponse.IDToken); err != nil {
		t.logger.Errorf("Failed to verify id_token during callback: %v", err)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not verify ID token", http.StatusInternalServerError)
		return
	}

	claims, err := t.extractClaimsFunc(tokenResponse.IDToken)
	if err != nil {
		t.logger.Errorf("Failed to extract claims during callback: %v", err)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not extract claims from token", http.StatusInternalServerError)
		return
	}

	// Verify nonce to prevent replay attacks
	nonceClaim, ok := claims["nonce"].(string)
	if !ok || nonceClaim == "" {
		t.logger.Error("Nonce claim missing in id_token during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce missing in token", http.StatusInternalServerError)
		return
	}

	sessionNonce := session.GetNonce()
	if sessionNonce == "" {
		t.logger.Error("Nonce not found in session during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce missing in session", http.StatusInternalServerError)
		return
	}

	if nonceClaim != sessionNonce {
		t.logger.Error("Nonce claim does not match session nonce during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce mismatch", http.StatusInternalServerError)
		return
	}

	// Validate user's email domain
	email, _ := claims["email"].(string)
	if email == "" {
		t.logger.Errorf("Email claim missing or empty in token during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: Email missing in token", http.StatusInternalServerError)
		return
	}
	if !t.isAllowedDomain(email) {
		t.logger.Errorf("Disallowed email domain during callback: %s", email)
		t.sendErrorResponse(rw, req, "Authentication failed: Email domain not allowed", http.StatusForbidden)
		return
	}

	// Update session with authentication data
	// Regenerate session ID upon successful authentication
	if err := session.SetAuthenticated(true); err != nil {
		t.logger.Errorf("Failed to set authenticated state and regenerate session ID: %v", err)
		http.Error(rw, "Failed to update session", http.StatusInternalServerError)
		return
	}
	session.SetEmail(email)
	session.SetAccessToken(tokenResponse.IDToken)
	session.SetRefreshToken(tokenResponse.RefreshToken)

	// Clear CSRF, Nonce, CodeVerifier after use
	session.SetCSRF("")
	session.SetNonce("")
	session.SetCodeVerifier("")

	// Retrieve original path *before* saving, as save might clear it if Clear was called concurrently
	redirectPath := "/"
	if incomingPath := session.GetIncomingPath(); incomingPath != "" && incomingPath != t.redirURLPath {
		redirectPath = incomingPath
	}
	session.SetIncomingPath("") // Clear incoming path after retrieving it

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session after callback: %v", err)
		http.Error(rw, "Failed to save session after callback", http.StatusInternalServerError)
		return
	}

	// Redirect to original path or root
	t.logger.Debugf("Callback successful, redirecting to %s", redirectPath)
	http.Redirect(rw, req, redirectPath, http.StatusFound)
}

// determineExcludedURL checks if the provided request path matches any of the configured excluded URL prefixes.
//
// Parameters:
//   - currentRequest: The path part of the incoming request URL.
//
// Returns:
//   - true if the path starts with any of the prefixes in the t.excludedURLs map.
//   - false otherwise.
func (t *TraefikOidc) determineExcludedURL(currentRequest string) bool {
	for excludedURL := range t.excludedURLs {
		if strings.HasPrefix(currentRequest, excludedURL) {
			t.logger.Debugf("URL is excluded - got %s / excluded hit: %s", currentRequest, excludedURL)
			return true
		}
	}
	// t.logger.Debugf("URL is not excluded - got %s", currentRequest) // Too verbose for every request
	return false
}

// determineIncludedURL checks if the provided request path matches any of the configured included URL prefixes.
//
// Parameters:
//   - currentRequest: The path part of the incoming request URL.
//
// Returns:
//   - true if the path starts with any of the prefixes in the t.includedURLs map.
//   - false otherwise.
func (t *TraefikOidc) determineIncludedURL(currentRequest string) bool {
	for includedURL := range t.includedURLs {
		if strings.HasPrefix(currentRequest, includedURL) {
			t.logger.Debugf("URL is included - got %s / included hit: %s", currentRequest, includedURL)
			return true
		}
	}
	// t.logger.Debugf("URL is not included - got %s", currentRequest) // Too verbose for every request
	return false
}

// determineScheme determines the request scheme (http or https).
// It prioritizes the X-Forwarded-Proto header if present, otherwise checks
// the TLS property of the request. Defaults to "http".
//
// Parameters:
//   - req: The incoming HTTP request.
//
// Returns:
//   - "https" or "http".
func (t *TraefikOidc) determineScheme(req *http.Request) string {
	if scheme := req.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

// determineHost determines the request host.
// It prioritizes the X-Forwarded-Host header if present, otherwise uses the req.Host value.
//
// Parameters:
//   - req: The incoming HTTP request.
//
// Returns:
//   - The determined host string (e.g., "example.com:8080").
func (t *TraefikOidc) determineHost(req *http.Request) string {
	if host := req.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return req.Host
}

// isUserAuthenticated checks the authentication status based on the provided session data.
// It verifies the session's authenticated flag, the presence and validity of the access token (ID token),
// including signature and standard claims (using VerifyJWTSignatureAndClaims). It also checks if the
// token is within the configured refreshGracePeriod before its actual expiration.
//
// Parameters:
//   - session: The SessionData object for the current user.
//
// Returns:
//   - authenticated (bool): True if the session is marked authenticated and the token is present and valid (signature/claims ok, not expired beyond grace).
//   - needsRefresh (bool): True if the token is valid but nearing expiration (within refreshGracePeriod) OR if VerifyJWTSignatureAndClaims failed specifically due to expiration (meaning refresh might be possible).
//   - expired (bool): True if the session is unauthenticated, the token is missing, or the token verification failed for reasons other than nearing/actual expiration (e.g., invalid signature, invalid claims).
func (t *TraefikOidc) isUserAuthenticated(session *SessionData) (bool, bool, bool) {
	if !session.GetAuthenticated() {
		t.logger.Debug("User is not authenticated according to session flag")
		// Check if there's still a refresh token - if so, refresh might be possible
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Session not authenticated, but refresh token exists. Signaling need for refresh.")
			return false, true, false // Not authenticated, NeedsRefresh=true (to attempt recovery), Expired=false
		}
		return false, false, false // Not authenticated, no refresh token, definitely not expired (just unauth)
	}

	accessToken := session.GetAccessToken()
	if accessToken == "" {
		t.logger.Debug("Authenticated flag set, but no access token found in session")
		// If authenticated flag is true but token is missing, treat as expired/invalid session state
		// Check for refresh token before declaring fully expired
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Authenticated flag set, access token missing, but refresh token exists. Signaling need for refresh.")
			return false, true, false // Not authenticated (no access token), NeedsRefresh=true, Expired=false
		}
		return false, false, true // No access or refresh token, treat as expired
	}

	// Verify the token structure and signature first
	jwt, err := parseJWT(accessToken)
	if err != nil {
		t.logger.Errorf("Failed to parse JWT during auth check: %v", err)
		// Check for refresh token before declaring fully expired
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Access token parsing failed, but refresh token exists. Signaling need for refresh.")
			return false, true, false // Not authenticated (bad access token), NeedsRefresh=true, Expired=false
		}
		return false, false, true // Invalid format, no refresh token, treat as expired/invalid
	}
	if err := t.VerifyJWTSignatureAndClaims(jwt, accessToken); err != nil {
		// Check if the error is specifically about expiration
		if strings.Contains(err.Error(), "token has expired") {
			t.logger.Debugf("Access token signature/claims valid but token expired, needs refresh")
			// Token is expired but otherwise valid, signal for refresh
			// Return authenticated=false because the current token is unusable
			// NeedsRefresh is true only if a refresh token exists
			if session.GetRefreshToken() != "" {
				return false, true, false // Not authenticated (current token unusable), NeedsRefresh=true, Expired=false (because refresh might fix it)
			}
			return false, false, true // Expired access token, no refresh token, treat as expired
		}
		// Other verification error (signature, issuer, audience etc.)
		t.logger.Errorf("Access token verification failed (non-expiration): %v", err)
		// Check for refresh token before declaring fully expired
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Access token verification failed, but refresh token exists. Signaling need for refresh.")
			return false, true, false // Not authenticated (bad access token), NeedsRefresh=true, Expired=false
		}
		return false, false, true // Token is invalid for other reasons, no refresh token, treat as expired/invalid session
	}

	// Claims already parsed within VerifyJWTSignatureAndClaims if it didn't error early
	claims := jwt.Claims

	expClaim, ok := claims["exp"].(float64)
	if !ok {
		t.logger.Error("Failed to get expiration time ('exp' claim) from verified token")
		// Check for refresh token before declaring fully expired
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Access token missing 'exp' claim, but refresh token exists. Signaling need for refresh.")
			return false, true, false // Not authenticated (bad access token), NeedsRefresh=true, Expired=false
		}
		return false, false, true // Treat as invalid if 'exp' is missing and no refresh token
	}

	expTime := int64(expClaim)

	// Expiration check is now handled within VerifyJWTSignatureAndClaims logic above
	// We only get here if the token is valid and not expired

	// Check if token is nearing expiration (needs refresh proactively)
	// Check if token is nearing expiration using the configured grace period
	if time.Unix(expTime, 0).Before(time.Now().Add(t.refreshGracePeriod)) {
		// Recalculate remaining seconds for logging clarity if needed, using the configured duration
		remainingSeconds := int64(time.Until(time.Unix(expTime, 0)).Seconds())
		t.logger.Debugf("Access token nearing expiration (expires in %d seconds, grace period %s), scheduling proactive refresh", remainingSeconds, t.refreshGracePeriod)
		// Token is still valid, but we should refresh it soon
		// NeedsRefresh is true only if a refresh token exists
		if session.GetRefreshToken() != "" {
			return true, true, false // Authenticated=true (current token usable), NeedsRefresh=true, Expired=false
		}
		// If no refresh token, we can't proactively refresh, treat as normal valid token for now
		t.logger.Debugf("Token nearing expiration but no refresh token available, cannot proactively refresh.")
		return true, false, false
	}

	// Token is valid, not expired, and not nearing expiration
	return true, false, false // Authenticated=true, NeedsRefresh=false, Expired=false
}

// defaultInitiateAuthentication handles the process of starting an OIDC authentication flow.
// It generates necessary security values (CSRF token, nonce, PKCE verifier/challenge if enabled),
// clears any potentially stale data from the current session, stores the new security values
// and the original request URI in the session, saves the session (setting cookies),
// builds the OIDC authorization endpoint URL with required parameters, and finally
// redirects the user's browser to that URL.
//
// Parameters:
//   - rw: The HTTP response writer used to send the redirect response.
//   - req: The original incoming HTTP request that requires authentication.
//   - session: The user's SessionData object (potentially new or cleared).
//   - redirectURL: The pre-calculated callback URL (redirect_uri) for this middleware instance.
func (t *TraefikOidc) defaultInitiateAuthentication(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	t.logger.Debugf("Initiating new OIDC authentication flow for request: %s", req.URL.RequestURI())
	// Generate CSRF token and nonce
	csrfToken := uuid.NewString()
	nonce, err := generateNonce()
	if err != nil {
		t.logger.Errorf("Failed to generate nonce: %v", err)
		http.Error(rw, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Generate PKCE code verifier and challenge if PKCE is enabled
	var codeVerifier, codeChallenge string
	if t.enablePKCE {
		var err error
		codeVerifier, err = generateCodeVerifier()
		if err != nil {
			t.logger.Errorf("Failed to generate code verifier: %v", err)
			http.Error(rw, "Failed to generate code verifier", http.StatusInternalServerError)
			return
		}
		codeChallenge = deriveCodeChallenge(codeVerifier)
		t.logger.Debugf("PKCE enabled, generated code challenge")
	}

	// Clear any existing session data to avoid stale state causing redirect loops
	// Pass the response writer to ensure expiring cookies are sent
	if err := session.Clear(req, rw); err != nil {
		// Log the error but continue, as clearing is best-effort before re-auth
		t.logger.Errorf("Error clearing session before initiating authentication: %v", err)
	}

	// Set new session values
	session.SetCSRF(csrfToken)
	session.SetNonce(nonce)
	if t.enablePKCE {
		session.SetCodeVerifier(codeVerifier)
	}
	// Store the original path the user was trying to access
	session.SetIncomingPath(req.URL.RequestURI())
	t.logger.Debugf("Storing incoming path: %s", req.URL.RequestURI())

	// Save the session (to store CSRF, Nonce, etc.)
	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session before redirecting to provider: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// Build and redirect to authentication URL
	authURL := t.buildAuthURL(redirectURL, csrfToken, nonce, codeChallenge)
	t.logger.Debugf("Redirecting user to OIDC provider: %s", authURL)
	http.Redirect(rw, req, authURL, http.StatusFound)
}

// verifyToken is a wrapper method that calls the VerifyToken method of the configured
// TokenVerifier interface (which defaults to the TraefikOidc instance itself).
// This primarily exists to facilitate testing and potential future extensions where
// token verification logic might be delegated differently.
//
// Parameters:
//   - token: The raw token string to verify.
//
// Returns:
//   - The result of calling t.tokenVerifier.VerifyToken(token).
func (t *TraefikOidc) verifyToken(token string) error {
	return t.tokenVerifier.VerifyToken(token)
}

// buildAuthURL constructs the OIDC authorization endpoint URL with all necessary query parameters
// for initiating the authorization code flow. It includes client_id, response_type, redirect_uri,
// state, nonce, and optionally PKCE parameters (code_challenge, code_challenge_method) if enabled
// and a challenge is provided. It also includes configured scopes.
//
// Parameters:
//   - redirectURL: The callback URL (redirect_uri).
//   - state: The CSRF token.
//   - nonce: The OIDC nonce.
//   - codeChallenge: The PKCE code challenge (can be empty if PKCE is disabled or not used).
//
// Returns:
//   - The fully constructed authorization URL string.
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

	// Handle scopes - ensure offline_access is included for refresh tokens
	scopes := make([]string, len(t.scopes))
	copy(scopes, t.scopes)

	// Check if we're dealing with a Google OIDC provider
	isGoogleProvider := strings.Contains(t.issuerURL, "google") || strings.Contains(t.issuerURL, "accounts.google.com")

	// Add offline_access scope if it's missing
	hasOfflineAccess := false
	for _, scope := range scopes {
		if scope == "offline_access" {
			hasOfflineAccess = true
			break
		}
	}

	if !hasOfflineAccess {
		scopes = append(scopes, "offline_access")
	}

	if len(scopes) > 0 {
		params.Set("scope", strings.Join(scopes, " "))
	}

	// Add prompt=consent for Google to ensure refresh token is issued
	if isGoogleProvider {
		params.Set("prompt", "consent")
		t.logger.Debug("Google OIDC provider detected, added prompt=consent to ensure refresh tokens")
	}

	// Use buildURLWithParams which handles potential relative authURL from metadata
	return t.buildURLWithParams(t.authURL, params)
}

// buildURLWithParams takes a base URL and query parameters and constructs a full URL string.
// If the baseURL is relative (doesn't start with http/https), it prepends the scheme and host
// from the configured issuerURL. It then appends the encoded query parameters.
//
// Parameters:
//   - baseURL: The base URL (can be absolute or relative to the issuer).
//   - params: A url.Values map containing the query parameters to append.
//
// Returns:
//   - The fully constructed URL string with appended query parameters.
func (t *TraefikOidc) buildURLWithParams(baseURL string, params url.Values) string {
	// Ensure URL is absolute
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		// Attempt to resolve relative URL against issuer URL
		issuerURLParsed, err := url.Parse(t.issuerURL)
		if err == nil {
			baseURLParsed, err := url.Parse(baseURL)
			if err == nil {
				resolvedURL := issuerURLParsed.ResolveReference(baseURLParsed)
				resolvedURL.RawQuery = params.Encode()
				return resolvedURL.String()
			}
		}
		// Fallback if parsing fails - append params to potentially relative path
		t.logger.Errorf("Could not parse issuerURL or baseURL to resolve relative URL. BaseURL: %s, IssuerURL: %s", baseURL, t.issuerURL)
		return baseURL + "?" + params.Encode()
	}

	// If baseURL is already absolute
	u, err := url.Parse(baseURL)
	if err != nil {
		t.logger.Errorf("Could not parse absolute baseURL: %s. Error: %v", baseURL, err)
		// Fallback: append params directly
		return baseURL + "?" + params.Encode()
	}
	u.RawQuery = params.Encode()
	return u.String()
}

// startTokenCleanup starts background goroutines for periodically cleaning up
// the token cache, token blacklist cache, and JWK cache using the autoCleanupRoutine helper.
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

// RevokeToken handles local revocation of a token.
// It removes the token from the validation cache (tokenCache) and adds the raw
// token string to the blacklist cache (tokenBlacklist) with a default expiration (24h).
// This prevents the token from being validated successfully even if it hasn't expired yet.
// Note: This does *not* revoke the token with the OIDC provider.
//
// Parameters:
//   - token: The raw token string to revoke locally.
func (t *TraefikOidc) RevokeToken(token string) {
	// Remove from cache
	t.tokenCache.Delete(token)

	// Add to blacklist with default expiration
	expiry := time.Now().Add(24 * time.Hour) // or other appropriate duration
	// Use Set with a duration. Value 'true' is arbitrary, we only care about existence.
	t.tokenBlacklist.Set(token, true, time.Until(expiry))
	t.logger.Debugf("Locally revoked token (added to blacklist)")
}

// RevokeTokenWithProvider attempts to revoke a token directly with the OIDC provider
// using the revocation endpoint specified in the provider metadata or configuration.
// It sends a POST request with the token, token_type_hint, client_id, and client_secret.
//
// Parameters:
//   - token: The token (e.g., refresh token or access token) to revoke.
//   - tokenType: The type hint for the token being revoked (e.g., "refresh_token").
//
// Returns:
//   - nil if the revocation request is successful (provider returns 200 OK).
//   - An error if the request fails or the provider returns a non-OK status.
func (t *TraefikOidc) RevokeTokenWithProvider(token, tokenType string) error {
	if t.revocationURL == "" {
		return fmt.Errorf("token revocation endpoint is not configured or discovered")
	}
	t.logger.Debugf("Attempting to revoke token (type: %s) with provider at %s", tokenType, t.revocationURL)

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
	req.Header.Set("Accept", "application/json") // Prefer JSON response if available

	// Send the request
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send token revocation request: %w", err)
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Log the failure details
		t.logger.Errorf("Token revocation failed with status %d: %s", resp.StatusCode, string(body))
		return fmt.Errorf("token revocation failed with status %d", resp.StatusCode)
	}

	t.logger.Debugf("Token successfully revoked with provider")
	return nil
}

// refreshToken attempts to use the refresh token stored in the session to obtain a new set of tokens.
// It acquires a mutex associated with the session to prevent concurrent refresh attempts for the same session.
// It retrieves the refresh token, calls the TokenExchanger's GetNewTokenWithRefreshToken method,
// verifies the newly obtained ID token using verifyToken, performs a concurrency check,
// updates the session with the new tokens if the check passes, and saves the session.
//
// Parameters:
//   - rw: The HTTP response writer (needed for saving the updated session).
//   - req: The HTTP request (needed for saving the updated session).
//   - session: The user's SessionData object containing the refresh token.
//
// Returns:
//   - true if the token refresh was successful and the session was updated.
//   - false if no refresh token was found, the refresh exchange failed, the new token failed verification,
//     a concurrency conflict was detected, or saving the session failed.
func (t *TraefikOidc) refreshToken(rw http.ResponseWriter, req *http.Request, session *SessionData) bool {
	// Lock the mutex specific to this session instance before attempting refresh
	session.refreshMutex.Lock()
	defer session.refreshMutex.Unlock()

	t.logger.Debug("Attempting to refresh token (mutex acquired)")
	initialRefreshToken := session.GetRefreshToken() // Get token *after* acquiring lock
	if initialRefreshToken == "" {
		t.logger.Errorf("refreshToken failed: No refresh token found in session (after acquiring lock)")
		return false
	}

	// Detect if we're using Google's OIDC provider
	isGoogleProvider := strings.Contains(t.issuerURL, "google") || strings.Contains(t.issuerURL, "accounts.google.com")
	if isGoogleProvider {
		t.logger.Debug("Google OIDC provider detected for token refresh operation")
	}

	// Log the attempt with a truncated token for security
	tokenPrefix := initialRefreshToken
	if len(initialRefreshToken) > 10 {
		tokenPrefix = initialRefreshToken[:10]
	}
	t.logger.Debugf("Attempting refresh with token starting with %s...", tokenPrefix)

	// Attempt to refresh the token
	newToken, err := t.tokenExchanger.GetNewTokenWithRefreshToken(initialRefreshToken)
	if err != nil {
		// Log detailed error information
		t.logger.Errorf("refreshToken failed: Error from token refresh operation: %v", err)

		// Check for specific error patterns
		errMsg := err.Error()
		if strings.Contains(errMsg, "invalid_grant") || strings.Contains(errMsg, "token expired") {
			t.logger.Errorf("Refresh token appears to be expired or revoked: %v", err)
			// Don't keep trying with an invalid refresh token
			session.SetRefreshToken("")
			if err := session.Save(req, rw); err != nil {
				t.logger.Errorf("Failed to remove invalid refresh token from session: %v", err)
			}
		} else if strings.Contains(errMsg, "invalid_client") {
			t.logger.Errorf("Client credentials rejected: %v - check client_id and client_secret configuration", err)
		} else if isGoogleProvider && strings.Contains(errMsg, "invalid_request") {
			t.logger.Errorf("Google OIDC provider error: %v - check scope configuration includes 'offline_access' and prompt=consent is used during authentication", err)
		}

		return false
	}

	// Handle potentially missing tokens in the response
	if newToken.IDToken == "" {
		t.logger.Errorf("refreshToken failed: Provider did not return a new ID token")
		return false
	}

	// Verify the new access token (ID token)
	if err := t.verifyToken(newToken.IDToken); err != nil {
		truncatedNewToken := newToken.IDToken
		if len(newToken.IDToken) > 10 {
			truncatedNewToken = newToken.IDToken[:10]
		}
		t.logger.Errorf("refreshToken failed: Failed to verify newly obtained ID token starting with %s...: %v", truncatedNewToken, err)
		return false
	}

	// --- Concurrency Check ---
	// Before saving the new token, check if the session state (specifically the refresh token)
	// has been modified concurrently (e.g., by a logout or another auth initiation).
	currentRefreshToken := session.GetRefreshToken() // Get token again *after* the potentially long exchange
	if initialRefreshToken != currentRefreshToken {
		// Use Infof as Warnf doesn't exist
		t.logger.Infof("refreshToken aborted: Session refresh token changed concurrently during refresh attempt.")
		// Do not save the new tokens, as the session state is likely invalid/cleared.
		return false // Indicate refresh failure due to concurrency conflict
	}
	// --- End Concurrency Check ---

	// Update session with new tokens ONLY if the concurrency check passed
	t.logger.Debugf("Concurrency check passed. Updating session with new tokens.")

	// Extract email from the new token and update session
	claims, err := t.extractClaimsFunc(newToken.IDToken)
	if err != nil {
		t.logger.Errorf("refreshToken failed: Failed to extract claims from refreshed token: %v", err)
		return false // Cannot proceed without claims
	}
	email, _ := claims["email"].(string)
	if email == "" {
		t.logger.Errorf("refreshToken failed: Email claim missing or empty in refreshed token")
		return false // Cannot proceed without email
	}
	session.SetEmail(email) // Update email in session

	// Get token expiry information for logging
	var expiryTime time.Time
	if expClaim, ok := claims["exp"].(float64); ok {
		expiryTime = time.Unix(int64(expClaim), 0)
		t.logger.Debugf("New token expires at: %v (in %v)", expiryTime, time.Until(expiryTime))
	}

	// Set the new access token
	session.SetAccessToken(newToken.IDToken)

	// Handle the refresh token
	if newToken.RefreshToken != "" {
		t.logger.Debug("Received new refresh token from provider")
		session.SetRefreshToken(newToken.RefreshToken)
	} else {
		// If no new refresh token is returned, keep the existing one
		t.logger.Debug("Provider did not return a new refresh token, keeping the existing one")
		session.SetRefreshToken(initialRefreshToken)
	}

	// Ensure authenticated flag is set
	if err := session.SetAuthenticated(true); err != nil {
		t.logger.Errorf("refreshToken warning: Failed to set authenticated flag: %v", err)
		// Continue anyway since we have valid tokens
	}

	// Save the session
	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("refreshToken failed: Failed to save session after successful token refresh: %v", err)
		return false
	}

	t.logger.Debugf("Token refresh successful and session saved")
	return true
}

// isAllowedDomain checks if the domain part of the provided email address is present
// in the configured list of allowed domains (t.allowedUserDomains).
// If the allowed domains list is empty, all domains are considered allowed.
//
// Parameters:
//   - email: The email address to check.
//
// Returns:
//   - true if the domain is allowed or if no domain restrictions are configured.
//   - false if the email format is invalid or the domain is not in the allowed list.
func (t *TraefikOidc) isAllowedDomain(email string) bool {
	if len(t.allowedUserDomains) == 0 {
		return true // If no domains are specified, all are allowed
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		t.logger.Errorf("Invalid email format encountered: %s", email)
		return false // Invalid email format
	}

	domain := parts[1]
	_, ok := t.allowedUserDomains[domain]
	return ok
}

// extractGroupsAndRoles attempts to extract 'groups' and 'roles' claims from a decoded ID token.
// It expects these claims, if present, to be arrays of strings.
// It uses the configured extractClaimsFunc (which defaults to the package-level extractClaims)
// to get the claims map from the token string.
//
// Parameters:
//   - idToken: The raw ID token string.
//
// Returns:
//   - A slice of strings containing the groups found in the 'groups' claim.
//   - A slice of strings containing the roles found in the 'roles' claim.
//   - An error if claim extraction fails or if the 'groups' or 'roles' claims are present but not arrays of strings.
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
			// Strictly expect an array
			return nil, nil, fmt.Errorf("groups claim is not an array")
		} else {
			for _, group := range groupsSlice {
				if groupStr, ok := group.(string); ok {
					t.logger.Debugf("Found group: %s", groupStr)
					groups = append(groups, groupStr)
				} else {
					t.logger.Errorf("Non-string value found in groups claim array: %v", group)
				}
			}
		}
	}

	// Extract roles with type checking
	if rolesClaim, exists := claims["roles"]; exists {
		rolesSlice, ok := rolesClaim.([]interface{})
		if !ok {
			// Strictly expect an array
			return nil, nil, fmt.Errorf("roles claim is not an array")
		} else {
			for _, role := range rolesSlice {
				if roleStr, ok := role.(string); ok {
					t.logger.Debugf("Found role: %s", roleStr)
					roles = append(roles, roleStr)
				} else {
					t.logger.Errorf("Non-string value found in roles claim array: %v", role)
				}
			}
		}
	}

	return groups, roles, nil
}

// buildFullURL constructs an absolute URL string from its components.
// If the provided path already starts with "http://" or "https://", it's returned directly.
// Otherwise, it combines the scheme, host, and path, ensuring the path starts with a '/'.
//
// Parameters:
//   - scheme: The URL scheme ("http" or "https").
//   - host: The host part of the URL (e.g., "example.com:8080").
//   - path: The path part of the URL (e.g., "/resource").
//
// Returns:
//   - The combined absolute URL string (e.g., "https://example.com:8080/resource").
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

// ExchangeCodeForToken provides the implementation for the TokenExchanger interface method.
// It directly calls the internal exchangeTokens method, passing through the arguments.
// This allows the TraefikOidc struct to act as its own default TokenExchanger, while
// still allowing mocking for tests.
func (t *TraefikOidc) ExchangeCodeForToken(ctx context.Context, grantType string, codeOrToken string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
	// Note: The original exchangeTokens helper is defined in helpers.go and is already a method on *TraefikOidc
	return t.exchangeTokens(ctx, grantType, codeOrToken, redirectURL, codeVerifier)
}

// GetNewTokenWithRefreshToken provides the implementation for the TokenExchanger interface method.
// It directly calls the internal getNewTokenWithRefreshToken helper method.
// This allows the TraefikOidc struct to act as its own default TokenExchanger, while
// still allowing mocking for tests.
func (t *TraefikOidc) GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	// Note: The original getNewTokenWithRefreshToken helper is defined in helpers.go and is already a method on *TraefikOidc
	return t.getNewTokenWithRefreshToken(refreshToken)
}

// sendErrorResponse sends an error response to the client, adapting the format based
// on the request's Accept header. If the client prefers "application/json", it sends
// a JSON object with "error", "error_description", and "status_code" fields.
// Otherwise, it sends a basic HTML error page containing the message and a link
// back to the application root or the original incoming path (if available from the session).
//
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The HTTP request (used to check Accept header and potentially get session).
//   - message: The error message to display/include in the response.
//   - code: The HTTP status code to set for the response.
func (t *TraefikOidc) sendErrorResponse(rw http.ResponseWriter, req *http.Request, message string, code int) {
	acceptHeader := req.Header.Get("Accept")

	// Check if the client prefers JSON
	if strings.Contains(acceptHeader, "application/json") {
		t.logger.Debugf("Sending JSON error response (code %d): %s", code, message)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(code)
		// Use a simple error structure
		json.NewEncoder(rw).Encode(map[string]interface{}{
			"error":             http.StatusText(code), // Use standard text for the code
			"error_description": message,               // Provide specific detail here
			"status_code":       code,
		})
		return
	}

	// Default to HTML response for browsers
	t.logger.Debugf("Sending HTML error response (code %d): %s", code, message)

	// Determine the return URL (mostly relevant for HTML)
	returnURL := "/" // Default to root
	// No need to get session here, as we are already in an error path
	// where session might be invalid or unavailable.

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
</html>`, message, returnURL) // Use default returnURL

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(code)
	_, _ = rw.Write([]byte(htmlBody)) // Ignore write error as header is already sent
}
