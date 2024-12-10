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
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

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
	tokenBlacklist             *TokenBlacklist
	jwksURL                    string
	clientID                   string
	clientSecret               string
	authURL                    string
	tokenURL                   string
	scopes                     []string
	limiter                    *rate.Limiter
	forceHTTPS                 bool
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
	exchangeCodeForTokenFunc   func(code string, redirectURL string) (*TokenResponse, error)
	extractClaimsFunc          func(tokenString string) (map[string]interface{}, error)
	initComplete               chan struct{}
	endSessionURL              string
	baseURL                    string
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

var newTicker = time.NewTicker

var (
	globalMetadataCache struct {
		sync.Once
		metadata *ProviderMetadata
		err      error
	}
)

// VerifyToken verifies the provided JWT token
func (t *TraefikOidc) VerifyToken(token string) error {
	t.logger.Debugf("Verifying token")

	// Rate limiting
	if !t.limiter.Allow() {
		return fmt.Errorf("rate limit exceeded")
	}

	// Check if token is blacklisted
	if t.tokenBlacklist.IsBlacklisted(token) {
		return fmt.Errorf("token is blacklisted")
	}

	// Check if token is cached
	if _, exists := t.tokenCache.Get(token); exists {
		t.logger.Debugf("Token is valid and cached")
		return nil // Token is valid and cached
	}

	// Parse the JWT
	jwt, err := parseJWT(token)
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Verify JWT signature and claims
	if err := t.VerifyJWTSignatureAndClaims(jwt, token); err != nil {
		return err
	}

	// Cache the token until it expires
	expirationTime := time.Unix(int64(jwt.Claims["exp"].(float64)), 0)
	now := time.Now()
	duration := expirationTime.Sub(now)
	t.tokenCache.Set(token, jwt.Claims, duration)

	return nil
}

// VerifyJWTSignatureAndClaims verifies the JWT signature and standard claims
func (t *TraefikOidc) VerifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	t.logger.Debugf("Verifying JWT signature and claims")

	// Get JWKS
	jwks, err := t.jwkCache.GetJWKS(t.jwksURL, t.httpClient)
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

// New creates a new instance of the OIDC middleware
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Setup HTTP client
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 0,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
	}

	var httpClient *http.Client
	if config.HTTPClient != nil {
		httpClient = config.HTTPClient
	} else {
		httpClient = &http.Client{
			Timeout:   time.Second * 30,
			Transport: transport,
		}
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
		clientID:              config.ClientID,
		clientSecret:          config.ClientSecret,
		forceHTTPS:            config.ForceHTTPS,
		scopes:                config.Scopes,
		limiter:               rate.NewLimiter(rate.Every(time.Second), config.RateLimit),
		tokenCache:            NewTokenCache(),
		httpClient:            httpClient,
		logger:                NewLogger(config.LogLevel),
		excludedURLs:          createStringMap(config.ExcludedURLs),
		allowedUserDomains:    createStringMap(config.AllowedUserDomains),
		allowedRolesAndGroups: createStringMap(config.AllowedRolesAndGroups),
		initComplete:          make(chan struct{}),
	}

	t.sessionManager = NewSessionManager(config.SessionEncryptionKey, config.ForceHTTPS, t.logger)
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
	globalMetadataCache.Once.Do(func() {
		t.logger.Debug("Starting global provider metadata discovery")
		metadata, err := discoverProviderMetadata(providerURL, t.httpClient, t.logger)
		globalMetadataCache.metadata = metadata
		globalMetadataCache.err = err
	})

	if globalMetadataCache.err != nil {
		t.logger.Errorf("Failed to discover provider metadata: %v", globalMetadataCache.err)
	} else if globalMetadataCache.metadata != nil {
		t.logger.Debug("Using cached provider metadata")
		t.jwksURL = globalMetadataCache.metadata.JWKSURL
		t.authURL = globalMetadataCache.metadata.AuthURL
		t.tokenURL = globalMetadataCache.metadata.TokenURL
		t.issuerURL = globalMetadataCache.metadata.Issuer
		t.revocationURL = globalMetadataCache.metadata.RevokeURL
		t.endSessionURL = globalMetadataCache.metadata.EndSessionURL
	}

	close(t.initComplete)
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

// ServeHTTP is the main handler for the middleware
func (t *TraefikOidc) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	select {
	case <-t.initComplete:
		if t.issuerURL == "" {
			t.logger.Debug("OIDC middleware not yet initialized")
			http.Error(rw, "OIDC middleware not yet initialized", http.StatusInternalServerError)
			return
		}
	case <-req.Context().Done():
		t.logger.Debug("Request cancelled")
		http.Error(rw, "Request cancelled", http.StatusServiceUnavailable)
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
		http.Error(rw, "Session error", http.StatusInternalServerError)
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

	// Set user information in headers
	req.Header.Set("X-Forwarded-User", email)

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
	if t.forceHTTPS {
		return "https"
	}
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

// isUserAuthenticated checks if the user is authenticated
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

// defaultInitiateAuthentication initiates the authentication process
func (t *TraefikOidc) defaultInitiateAuthentication(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	// Generate CSRF token and nonce
	csrfToken := uuid.New().String()
	nonce, err := generateNonce()
	if err != nil {
		http.Error(rw, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Set session values
	session.SetCSRF(csrfToken)
	session.SetNonce(nonce)
	session.SetIncomingPath(req.URL.Path)

	// Save the session
	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// Build and redirect to auth URL
	authURL := t.buildAuthURL(redirectURL, csrfToken, nonce)
	http.Redirect(rw, req, authURL, http.StatusFound)
}

// verifyToken verifies the token using the token verifier
func (t *TraefikOidc) verifyToken(token string) error {
	return t.tokenVerifier.VerifyToken(token)
}

// buildAuthURL constructs the authentication URL
func (t *TraefikOidc) buildAuthURL(redirectURL, state, nonce string) string {
	params := url.Values{}
	params.Set("client_id", t.clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURL)
	params.Set("state", state)
	params.Set("nonce", nonce)
	if len(t.scopes) > 0 {
		params.Set("scope", strings.Join(t.scopes, " "))
	}
	return t.authURL + "?" + params.Encode()
}

// startTokenCleanup starts the token cleanup goroutine
func (t *TraefikOidc) startTokenCleanup() {
	ticker := newTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			t.logger.Debug("Cleaning up token cache")
			t.tokenCache.Cleanup()
			t.tokenBlacklist.Cleanup()
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
