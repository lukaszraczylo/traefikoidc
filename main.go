package traefikoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
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
	next               http.Handler
	name               string
	store              sessions.Store
	redirURLPath       string
	logoutURLPath      string
	issuerURL          string
	revocationURL      string
	jwkCache           *JWKCache
	tokenBlacklist     *TokenBlacklist
	jwksURL            string
	clientID           string
	clientSecret       string
	authURL            string
	tokenURL           string
	scopes             []string
	limiter            *rate.Limiter
	forceHTTPS         bool
	scheme             string
	tokenCache         *TokenCache
	httpClient         *http.Client
	logger             *Logger
	redirectURL        string
	tokenVerifier      TokenVerifier
	jwtVerifier        JWTVerifier
	excludedURLs       map[string]struct{}
	allowedUserDomains map[string]struct{}
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

func (t *TraefikOidc) VerifyToken(token string) error {
	t.logger.Debugf("Verifying token")
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
	t.tokenCache.Set(token, expirationTime)

	return nil
}

func (t *TraefikOidc) VerifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	jwks, err := t.jwkCache.GetJWKS(t.jwksURL, t.httpClient)
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	kid, ok := jwt.Header["kid"].(string)
	if !ok {
		return fmt.Errorf("missing key ID in token header")
	}

	publicKeys := make(map[string][]byte)
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			publicKeyPEM, err := jwkToPEM(&key)
			if err != nil {
				return err
			}
			publicKeys[key.Kid] = publicKeyPEM
		}
	}

	if len(publicKeys) == 0 {
		return fmt.Errorf("no matching public keys found")
	}

	if err := t.verifySignatureConcurrently(token, publicKeys); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return jwt.Verify(t.issuerURL, t.clientID)
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	store := sessions.NewCookieStore([]byte(config.SessionEncryptionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   ConstSessionTimeout,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	metadata, err := discoverProviderMetadata(config.ProviderURL, http.Client{})
	if err != nil {
		return nil, fmt.Errorf("failed to discover provider metadata: %w", err)
	}

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
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   10,
	}

	httpClient := &http.Client{
		Timeout:   time.Second * 30,
		Transport: transport,
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
		issuerURL:      metadata.Issuer,
		revocationURL:  metadata.RevokeURL,
		tokenBlacklist: NewTokenBlacklist(),
		jwkCache:       &JWKCache{},
		jwksURL:        metadata.JWKSURL,
		clientID:       config.ClientID,
		clientSecret:   config.ClientSecret,
		forceHTTPS:     config.ForceHTTPS,
		authURL:        metadata.AuthURL,
		tokenURL:       metadata.TokenURL,
		scopes:         config.Scopes,
		limiter:        rate.NewLimiter(rate.Every(time.Second), config.RateLimit),
		tokenCache:     NewTokenCache(),
		httpClient:     httpClient,
		logger:         NewLogger(config.LogLevel),
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
	}
	// add defaultExcludedURLs to excludedURLs
	for k, v := range defaultExcludedURLs {
		t.excludedURLs[k] = v
	}

	t.tokenVerifier = t
	t.jwtVerifier = t
	t.startTokenCleanup()
	return t, nil
}

func discoverProviderMetadata(providerURL string, httpClient http.Client) (*ProviderMetadata, error) {
	wellKnownURL := strings.TrimSuffix(providerURL, "/") + "/.well-known/openid-configuration"
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
	// Check if the URL is excluded first
	if t.determineExcludedURL(req.URL.Path) {
		t.next.ServeHTTP(rw, req)
		return
	}

	t.scheme = t.determineScheme(req)
	host := t.determineHost(req)

	if req.URL.Path == t.logoutURLPath {
		t.handleLogout(rw, req)
		return
	}

	if t.redirectURL == "" {
		t.redirectURL = buildFullURL(t.scheme, host, t.redirURLPath)
		t.logger.Debugf("Redirect URL updated to: %s", t.redirectURL)
	}

	// Only get or create a session if the URL is not excluded
	session, err := t.store.Get(req, cookieName)
	if err != nil {
		t.logger.Errorf("Error getting session: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	if req.URL.Path == t.redirURLPath {
		t.logger.Debugf("Handling callback, URL: %s", req.URL.String())
		authSuccess, originalPath := t.handleCallback(rw, req)
		if authSuccess {
			http.Redirect(rw, req, originalPath, http.StatusFound)
			return
		}
		if !authSuccess && originalPath == "invalid-state-param" {
			// redirect to the root path so that the user can try again
			// this usually happens when user was previously authenticated
			// and the session was cleared, but user tries to refresh the page
			// and different traefik instance is used.
			http.Redirect(rw, req, "/", http.StatusFound)
			return
		}
		http.Error(rw, "Authentication failed", http.StatusUnauthorized)
		return
	}

	authenticated, needsRefresh, expired := t.isUserAuthenticated(session)

	if expired || !authenticated {
		t.initiateAuthentication(rw, req, session, t.redirectURL)
		return
	}

	if needsRefresh {
		refreshed := t.refreshToken(rw, req, session)
		if !refreshed {
			t.initiateAuthentication(rw, req, session, t.redirectURL)
			return
		}
	}

	if authenticated {
		idToken, ok := session.Values["id_token"].(string)
		if !ok || idToken == "" {
			t.logger.Errorf("No id_token found in session")
			t.initiateAuthentication(rw, req, session, t.redirectURL)
			return
		}

		claims, err := extractClaims(idToken)
		if err != nil {
			t.logger.Errorf("Failed to extract claims: %v", err)
			t.initiateAuthentication(rw, req, session, t.redirectURL)
			return
		}

		email, _ := claims["email"].(string)
		if email == "" {
			t.logger.Debugf("No email found in token claims")
			t.initiateAuthentication(rw, req, session, t.redirectURL)
			return
		}

		if !t.isAllowedDomain(email) {
			t.logger.Infof("User with email %s is not from an allowed domain", email)
			http.Error(rw, fmt.Sprintf("Access denied: Your email domain is not allowed. To log out, visit: %s", t.logoutURLPath), http.StatusForbidden)
			return
		}

		req.Header.Set("X-Forwarded-User", email)

		t.next.ServeHTTP(rw, req)
		return
	}

	// If the user is not authenticated, initiate authentication
	t.initiateAuthentication(rw, req, session, t.redirectURL)
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
	if !authenticated {
		return false, false, false
	}

	idToken, ok := session.Values["id_token"].(string)
	if !ok || idToken == "" {
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

	exp, ok := claims["exp"].(float64)
	if !ok {
		t.logger.Errorf("Failed to get expiration time from claims")
		return false, false, true // No expiration, consider it expired
	}

	now := time.Now().Unix()
	expTime := int64(exp)

	if now > expTime {
		return false, false, true // Token has expired
	}

	gracePeriod := time.Minute * 5
	if time.Now().Add(gracePeriod).Unix() > expTime {
		return true, true, false // Token will expire soon, needs refresh
	}

	return true, false, false // Token is valid and not expiring soon
}

func (t *TraefikOidc) initiateAuthentication(rw http.ResponseWriter, req *http.Request, session *sessions.Session, redirectURL string) {
	csrfToken := uuid.New().String()
	session.Values["csrf"] = csrfToken
	session.Values["incoming_path"] = req.URL.Path
	t.logger.Debugf("Setting CSRF token: %s", csrfToken)

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	nonce, err := generateNonce()
	if err != nil {
		http.Error(rw, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	authURL := t.buildAuthURL(redirectURL, csrfToken, nonce)
	http.Redirect(rw, req, authURL, http.StatusFound)
}

func (t *TraefikOidc) verifyToken(token string) error {
	return t.tokenVerifier.VerifyToken(token)
}

var authURLBuilder strings.Builder

func (t *TraefikOidc) buildAuthURL(redirectURL, state, nonce string) string {
	authURLBuilder.Reset()
	authURLBuilder.Grow(256) // Pre-allocate some space
	authURLBuilder.WriteString(t.authURL)
	authURLBuilder.WriteString("?client_id=")
	authURLBuilder.WriteString(t.clientID)
	authURLBuilder.WriteString("&response_type=code&redirect_uri=")
	authURLBuilder.WriteString(url.QueryEscape(redirectURL))
	authURLBuilder.WriteString("&state=")
	authURLBuilder.WriteString(state)
	authURLBuilder.WriteString("&nonce=")
	authURLBuilder.WriteString(nonce)

	if len(t.scopes) > 0 {
		authURLBuilder.WriteString("&scope=")
		authURLBuilder.WriteString(strings.Join(t.scopes, "+"))
	}

	return authURLBuilder.String()
}

func (t *TraefikOidc) startTokenCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
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
