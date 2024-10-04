package traefikoidc

import (
	"context"
	"encoding/base64"
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
	"github.com/gorilla/sessions"
	"golang.org/x/time/rate"
)

const ConstSessionTimeout = 86400

type TokenVerifier interface {
	VerifyToken(token string) error
}

type JWTVerifier interface {
	VerifyJWTSignatureAndClaims(jwt *JWT, token string) error
}

type TraefikOidc struct {
	next                       http.Handler
	name                       string
	store                      sessions.Store
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
	redirectURL                string
	tokenVerifier              TokenVerifier
	jwtVerifier                JWTVerifier
	excludedURLs               map[string]struct{}
	allowedUserDomains         map[string]struct{}
	allowedRolesAndGroups      map[string]struct{}
	initiateAuthenticationFunc func(rw http.ResponseWriter, req *http.Request, session *sessions.Session, redirectURL string)
	exchangeCodeForTokenFunc   func(code string) (map[string]interface{}, error)
	extractClaimsFunc          func(tokenString string) (map[string]interface{}, error)
	initOnce                   sync.Once
	initComplete               chan struct{}
}

type ProviderMetadata struct {
	Issuer    string `json:"issuer"`
	AuthURL   string `json:"authorization_endpoint"`
	TokenURL  string `json:"token_endpoint"`
	JWKSURL   string `json:"jwks_uri"`
	RevokeURL string `json:"revocation_endpoint"`
}

var defaultExcludedURLs = map[string]struct{}{
	"/favicon": {},
}

var newTicker = time.NewTicker

func (t *TraefikOidc) VerifyToken(token string) error {
	t.logger.Debugf("Verifying token: %s", token)
	if !t.limiter.Allow() {
		return fmt.Errorf("rate limit exceeded")
	}

	if t.tokenBlacklist.IsBlacklisted(token) {
		return fmt.Errorf("token is blacklisted")
	}

	if _, exists := t.tokenCache.Get(token); exists {
		t.logger.Debugf("Token is valid and cached")
		return nil // Token is valid and cached
	}

	jwt, err := parseJWT(token)
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	if err := t.VerifyJWTSignatureAndClaims(jwt, token); err != nil {
		return err
	}

	expirationTime := time.Unix(int64(jwt.Claims["exp"].(float64)), 0)
	now := time.Now()
	duration := expirationTime.Sub(now)
	t.tokenCache.Set(token, jwt.Claims, duration)

	return nil
}

func (t *TraefikOidc) VerifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	t.logger.Debugf("Verifying JWT. Header: %+v", jwt.Header)

	jwks, err := t.jwkCache.GetJWKS(t.jwksURL, t.httpClient)
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	kid, ok := jwt.Header["kid"].(string)
	if !ok {
		return fmt.Errorf("missing key ID in token header")
	}
	t.logger.Debugf("Token kid: %s", kid)

	alg, ok := jwt.Header["alg"].(string)
	if !ok {
		return fmt.Errorf("missing algorithm in token header")
	}
	t.logger.Debugf("Token alg: %s", alg)

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
	t.logger.Debugf("Matching key found. Type: %s, Algorithm: %s", matchingKey.Kty, matchingKey.Alg)

	publicKeyPEM, err := jwkToPEM(matchingKey)
	if err != nil {
		return fmt.Errorf("failed to convert JWK to PEM: %w", err)
	}
	t.logger.Debugf("Public key PEM generated. Length: %d", len(publicKeyPEM))

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}

	signedContent := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if err := verifySignature(signedContent, signature, publicKeyPEM, alg); err != nil {
		t.logger.Errorf("Signature verification failed: %v", err)
		return fmt.Errorf("signature verification failed: %w", err)
	}
	t.logger.Debug("Signature verified successfully")

	// Verify standard claims
	if err := jwt.Verify(t.issuerURL, t.clientID); err != nil {
		return fmt.Errorf("standard claim verification failed: %w", err)
	}
	t.logger.Debug("Standard claims verified successfully")

	return nil
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	store := sessions.NewCookieStore([]byte(config.SessionEncryptionKey))
	store.Options = defaultSessionOptions

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
		ExpectContinueTimeout: 1 * time.Second,
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
		store:        store,
		redirURLPath: config.CallbackURL,
		logoutURLPath: func() string {
			if config.LogoutURL == "" {
				return config.CallbackURL + "/logout"
			}
			return config.LogoutURL
		}(),
		tokenBlacklist: NewTokenBlacklist(),
		jwkCache:       &JWKCache{},

		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		forceHTTPS:   config.ForceHTTPS,
		scopes:       config.Scopes,
		limiter:      rate.NewLimiter(rate.Every(time.Second), config.RateLimit),
		tokenCache:   NewTokenCache(),
		httpClient:   httpClient,
		logger:       NewLogger(config.LogLevel),
		excludedURLs: func() map[string]struct{} {
			m := make(map[string]struct{})
			for _, url := range config.ExcludedURLs {
				m[url] = struct{}{}
			}
			return m
		}(),
		redirectURL: "",
		allowedUserDomains: func() map[string]struct{} {
			m := make(map[string]struct{})
			for _, domain := range config.AllowedUserDomains {
				m[domain] = struct{}{}
			}
			return m
		}(),
		allowedRolesAndGroups: func() map[string]struct{} {
			m := make(map[string]struct{})
			for _, roleOrGroup := range config.AllowedRolesAndGroups {
				m[roleOrGroup] = struct{}{}
			}
			return m
		}(),
		initComplete: make(chan struct{}),
	}

	t.initiateAuthenticationFunc = t.defaultInitiateAuthentication
	t.exchangeCodeForTokenFunc = t.exchangeCodeForToken
	t.extractClaimsFunc = extractClaims

	// add defaultExcludedURLs to excludedURLs
	for k, v := range defaultExcludedURLs {
		t.excludedURLs[k] = v
	}

	t.tokenVerifier = t
	t.jwtVerifier = t
	t.startTokenCleanup()
	go t.initializeMetadata(config.ProviderURL)

	return t, nil
}

func (t *TraefikOidc) initializeMetadata(providerURL string) {
	t.initOnce.Do(func() {
		metadata, err := discoverProviderMetadata(providerURL, t.httpClient, t.logger)
		if err != nil {
			t.logger.Error("Failed to discover provider metadata: %v", err)
		} else {
			t.logger.Debug("Provider metadata discovered successfully")
			t.jwksURL = metadata.JWKSURL
			t.authURL = metadata.AuthURL
			t.tokenURL = metadata.TokenURL
			t.issuerURL = metadata.Issuer
			t.revocationURL = metadata.RevokeURL
		}
		close(t.initComplete)
	})
}

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
			l.Error("Timeout exceeded while fetching provider metadata")
			return nil, fmt.Errorf("timeout exceeded while fetching provider metadata: %w", lastErr)
		}

		metadata, err := fetchMetadata(wellKnownURL, httpClient)
		if err == nil {
			l.Debug("Provider metadata fetched successfully")
			return metadata, nil
		}

		lastErr = err

		delay := time.Duration(math.Pow(2, float64(attempt))) * baseDelay
		if delay > maxDelay {
			delay = maxDelay
		}
		l.Debug("Failed to fetch provider metadata, retrying in %s", delay)
		time.Sleep(delay)
	}

	l.Error("Max retries exceeded while fetching provider metadata")
	return nil, fmt.Errorf("max retries exceeded while fetching provider metadata: %w", lastErr)
}

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

func (t *TraefikOidc) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	select {
	case <-t.initComplete:
		if t.issuerURL == "" {
			t.logger.Debug("OIDC middleware not yet initialized")
			http.Error(rw, "OIDC middleware not yet initialized", http.StatusInternalServerError)
			return
		}
		// Process the request as normal
	case <-req.Context().Done():
		t.logger.Debug("Request cancelled")
		http.Error(rw, "Request cancelled", http.StatusServiceUnavailable)
		return
	}

	if t.determineExcludedURL(req.URL.Path) {
		t.next.ServeHTTP(rw, req)
		return
	}

	t.scheme = t.determineScheme(req)
	defaultSessionOptions.Secure = t.scheme == "https"
	host := t.determineHost(req)

	if t.redirectURL == "" {
		t.redirectURL = buildFullURL(t.scheme, host, t.redirURLPath)
		t.logger.Debugf("Redirect URL updated to: %s", t.redirectURL)
	}

	session, err := t.store.Get(req, cookieName)
	if err != nil {
		t.logger.Errorf("Error getting session: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Session contents at start: %+v", session.Values)

	if req.URL.Path == t.logoutURLPath {
		t.handleLogout(rw, req)
		return
	}

	if req.URL.Path == t.redirURLPath {
		t.handleCallback(rw, req)
		return
	}

	authenticated, needsRefresh, expired := t.isUserAuthenticated(session)

	if expired {
		t.handleExpiredToken(rw, req, session)
		return
	}

	if !authenticated {
		t.defaultInitiateAuthentication(rw, req, session, t.redirectURL)
		return
	}

	if needsRefresh {
		refreshed := t.refreshToken(rw, req, session)
		if !refreshed {
			t.handleExpiredToken(rw, req, session)
			return
		}
	}

	// authenticated, _ := session.Values["authenticated"].(bool)
	if authenticated {
		idToken, ok := session.Values["id_token"].(string)
		if !ok || idToken == "" {
			t.logger.Errorf("No id_token found in session")
			t.defaultInitiateAuthentication(rw, req, session, t.redirectURL)
			return
		}

		claims, err := extractClaims(idToken)
		if err != nil {
			t.logger.Errorf("Failed to extract claims: %v", err)
			t.defaultInitiateAuthentication(rw, req, session, t.redirectURL)
			return
		}

		email, _ := claims["email"].(string)
		if email == "" {
			t.logger.Debugf("No email found in token claims")
			t.defaultInitiateAuthentication(rw, req, session, t.redirectURL)
			return
		}

		if !t.isAllowedDomain(email) {
			t.logger.Infof("User with email %s is not from an allowed domain", email)
			http.Error(rw, fmt.Sprintf("Access denied: Your email domain is not allowed. To log out, visit: %s", t.logoutURLPath), http.StatusForbidden)
			return
		}

		groups, roles, err := t.extractGroupsAndRoles(idToken)
		if err != nil {
			t.logger.Errorf("Failed to extract groups and roles: %v", err)
		} else {
			// Set headers for groups and roles
			if len(groups) > 0 {
				req.Header.Set("X-User-Groups", strings.Join(groups, ","))
			}
			if len(roles) > 0 {
				req.Header.Set("X-User-Roles", strings.Join(roles, ","))
			}
		}

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
				http.Error(rw, fmt.Sprintf("Access denied: You do not have any allowed roles or groups. To log out, visit: %s", t.logoutURLPath), http.StatusForbidden)
				return
			}
		}

		req.Header.Set("X-Forwarded-User", email)

		t.next.ServeHTTP(rw, req)
		return
	}

	t.logger.Debug("User is not authenticated, initiating authentication")
	t.defaultInitiateAuthentication(rw, req, session, t.redirectURL)
}

func (t *TraefikOidc) determineExcludedURL(currentRequest string) bool {
	for excludedURL := range t.excludedURLs {
		if strings.HasPrefix(currentRequest, excludedURL) {
			t.logger.Debug("URL is excluded - got %s / excluded hit: %s", currentRequest, excludedURL)
			return true
		}
	}
	t.logger.Debug("URL is not excluded - got %s", currentRequest)
	return false
}

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

func (t *TraefikOidc) determineHost(req *http.Request) string {
	if host := req.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return req.Host
}

func (t *TraefikOidc) isUserAuthenticated(session *sessions.Session) (bool, bool, bool) {
	authenticated, _ := session.Values["authenticated"].(bool)
	t.logger.Debugf("Session authenticated value: %v", authenticated)

	if !authenticated {
		t.logger.Debug("User is not authenticated according to session")
		return false, false, false
	}

	idToken, ok := session.Values["id_token"].(string)
	if !ok || idToken == "" {
		t.logger.Debug("No id_token found in session")
		return false, false, true // Session is invalid, consider it expired
	}

	// Verify the token
	if err := t.verifyToken(idToken); err != nil {
		t.logger.Errorf("Token verification failed: %v", err)
		return false, false, true // Token is invalid, consider it expired
	}

	claims, err := extractClaims(idToken)
	if err != nil {
		t.logger.Errorf("Failed to extract claims: %v", err)
		return false, false, true // Can't read claims, consider it expired
	}

	expClaim, ok := claims["exp"].(float64)
	if !ok {
		t.logger.Errorf("Failed to get expiration time from claims")
		return false, false, true // No expiration, consider it expired
	}

	now := time.Now().Unix()
	expTime := int64(expClaim)

	if now > expTime {
		t.logger.Debug("Token has expired")
		return false, false, true // Token has expired
	}

	gracePeriod := time.Minute * 5
	if now+int64(gracePeriod.Seconds()) > expTime {
		t.logger.Debug("Token will expire soon")
		return true, true, false // Token will expire soon, needs refresh
	}

	return true, false, false // Token is valid and not expiring soon
}

func (t *TraefikOidc) defaultInitiateAuthentication(rw http.ResponseWriter, req *http.Request, session *sessions.Session, redirectURL string) {
	csrfToken := uuid.New().String()
	session.Values["csrf"] = csrfToken
	session.Values["incoming_path"] = req.URL.Path
	session.Options = defaultSessionOptions
	t.logger.Debugf("Setting CSRF token: %s", csrfToken)

	nonce, err := generateNonce()
	if err != nil {
		http.Error(rw, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}
	session.Values["nonce"] = nonce
	t.logger.Debugf("Setting nonce: %s", nonce)

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	authURL := t.buildAuthURL(redirectURL, csrfToken, nonce)
	http.Redirect(rw, req, authURL, http.StatusFound)
}

func (t *TraefikOidc) verifyToken(token string) error {
	return t.tokenVerifier.VerifyToken(token)
}

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

func (t *TraefikOidc) RevokeToken(token string) {
	// Remove from cache
	t.tokenCache.Delete(token)

	// Add to blacklist
	claims, err := extractClaims(token)
	if err == nil {
		if exp, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			t.tokenBlacklist.Add(token, expTime)
		}
	}
}

func (t *TraefikOidc) RevokeTokenWithProvider(token string) error {
	t.logger.Debugf("Revoking token with provider")

	data := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token", "refresh_token"},
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

func (t *TraefikOidc) refreshToken(rw http.ResponseWriter, req *http.Request, session *sessions.Session) bool {
	t.logger.Debug("Refreshing token")
	refreshToken, ok := session.Values["refresh_token"].(string)
	if !ok || refreshToken == "" {
		return false
	}

	newToken, err := t.getNewTokenWithRefreshToken(refreshToken)
	if err != nil {
		t.logger.Errorf("Failed to refresh token: %v", err)
		return false
	}

	session.Values["id_token"] = newToken.IDToken
	session.Values["refresh_token"] = newToken.RefreshToken
	session.Options = defaultSessionOptions
	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save refreshed session: %v", err)
		return false
	}

	return true
}

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

func (t *TraefikOidc) extractGroupsAndRoles(idToken string) ([]string, []string, error) {
	claims, err := t.extractClaimsFunc(idToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	var groups []string
	var roles []string

	// Check for groups claim
	if groupsClaim, ok := claims["groups"]; ok {
		if groupsSlice, ok := groupsClaim.([]interface{}); ok {
			for _, group := range groupsSlice {
				if groupStr, ok := group.(string); ok {
					t.logger.Debugf("Found group: %s", groupStr)
					groups = append(groups, groupStr)
				}
			}
		}
	}

	if len(groups) == 0 {
		t.logger.Debug("No groups found in groups claim, checking roles claim")
	}

	// Check for roles claim
	if rolesClaim, ok := claims["roles"]; ok {
		if rolesSlice, ok := rolesClaim.([]interface{}); ok {
			for _, role := range rolesSlice {
				if roleStr, ok := role.(string); ok {
					t.logger.Debug("Found role: %s", roleStr)
					roles = append(roles, roleStr)
				}
			}
		}
	}

	if len(roles) == 0 {
		t.logger.Debug("No roles found in roles claim")
	}

	return groups, roles, nil
}
