package traefikoidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/sessions"
)

func newSessionOptions(isSecure bool) *sessions.Options {
	return &sessions.Options{
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   ConstSessionTimeout,
		Path:     "/",
	}
}

// generateNonce generates a random nonce
func generateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce: %w", err)
	}
	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

// exchangeTokens exchanges a code or refresh token for tokens
func (t *TraefikOidc) exchangeTokens(ctx context.Context, grantType, codeOrToken, redirectURL string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {grantType},
		"client_id":     {t.clientID},
		"client_secret": {t.clientSecret},
	}

	if grantType == "authorization_code" {
		data.Set("code", codeOrToken)
		data.Set("redirect_uri", redirectURL)
	} else if grantType == "refresh_token" {
		data.Set("refresh_token", codeOrToken)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", t.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange tokens: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResponse, nil
}

// TokenResponse represents the response from the token endpoint
type TokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// getNewTokenWithRefreshToken refreshes the token using the refresh token
func (t *TraefikOidc) getNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	ctx := context.Background()
	tokenResponse, err := t.exchangeTokens(ctx, "refresh_token", refreshToken, "")
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	t.logger.Debugf("Token response: %+v", tokenResponse)

	return tokenResponse, nil
}

// handleExpiredToken handles the case when a token has expired
func (t *TraefikOidc) handleExpiredToken(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	// Clear the existing session
	if err := session.Clear(req, rw); err != nil {
		t.logger.Errorf("Failed to clear session: %v", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Initialize new authentication
	t.defaultInitiateAuthentication(rw, req, session, redirectURL)
}

// handleCallback handles the callback from the OIDC provider
func (t *TraefikOidc) handleCallback(rw http.ResponseWriter, req *http.Request, redirectURL string) {
	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Session error: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Handling callback, URL: %s", req.URL.String())

	// Check for errors in the query parameters
	if req.URL.Query().Get("error") != "" {
		errorDescription := req.URL.Query().Get("error_description")
		t.logger.Errorf("Authentication error: %s - %s", req.URL.Query().Get("error"), errorDescription)
		http.Error(rw, fmt.Sprintf("Authentication error: %s", errorDescription), http.StatusBadRequest)
		return
	}

	// Validate state parameter matches the session's CSRF token
	state := req.URL.Query().Get("state")
	if state == "" {
		t.logger.Error("No state in callback")
		http.Error(rw, "State parameter missing in callback", http.StatusBadRequest)
		return
	}

	csrfToken := session.GetCSRF()
	if csrfToken == "" {
		t.logger.Error("CSRF token missing in session")
		http.Error(rw, "CSRF token missing", http.StatusBadRequest)
		return
	}

	if state != csrfToken {
		t.logger.Error("State parameter does not match CSRF token in session")
		http.Error(rw, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	code := req.URL.Query().Get("code")
	if code == "" {
		t.logger.Error("No code in callback")
		http.Error(rw, "No code in callback", http.StatusBadRequest)
		return
	}

	tokenResponse, err := t.exchangeCodeForTokenFunc(code, redirectURL)
	if err != nil {
		t.logger.Errorf("Failed to exchange code for token: %v", err)
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Verify and process tokens
	if err := t.verifyToken(tokenResponse.IDToken); err != nil {
		t.logger.Errorf("Failed to verify id_token: %v", err)
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	claims, err := t.extractClaimsFunc(tokenResponse.IDToken)
	if err != nil {
		t.logger.Errorf("Failed to extract claims: %v", err)
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Verify nonce
	nonceClaim, ok := claims["nonce"].(string)
	if !ok || nonceClaim == "" {
		t.logger.Error("Nonce claim missing in id_token")
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	sessionNonce := session.GetNonce()
	if sessionNonce == "" {
		t.logger.Error("Nonce not found in session")
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	if nonceClaim != sessionNonce {
		t.logger.Error("Nonce claim does not match session nonce")
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Process email
	email, _ := claims["email"].(string)
	if email == "" || !t.isAllowedDomain(email) {
		t.logger.Errorf("Invalid or disallowed email: %s", email)
		http.Error(rw, "Authentication failed: Invalid or disallowed email", http.StatusForbidden)
		return
	}

	// Update session with new values
	session.SetAuthenticated(true)
	session.SetEmail(email)
	session.SetAccessToken(tokenResponse.IDToken)
	session.SetRefreshToken(tokenResponse.RefreshToken)

	// Save session
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

// extractClaims extracts claims from a JWT token
func extractClaims(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return claims, nil
}

// TokenBlacklist maintains a blacklist of tokens
type TokenBlacklist struct {
	blacklist map[string]time.Time
	mutex     sync.RWMutex
}

// NewTokenBlacklist creates a new TokenBlacklist
func NewTokenBlacklist() *TokenBlacklist {
	return &TokenBlacklist{
		blacklist: make(map[string]time.Time),
	}
}

// Add adds a token to the blacklist
func (tb *TokenBlacklist) Add(tokenID string, expiration time.Time) {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()
	tb.blacklist[tokenID] = expiration
}

// IsBlacklisted checks if a token is blacklisted
func (tb *TokenBlacklist) IsBlacklisted(tokenID string) bool {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()
	expiration, exists := tb.blacklist[tokenID]
	return exists && time.Now().Before(expiration)
}

// Cleanup removes expired tokens from the blacklist
func (tb *TokenBlacklist) Cleanup() {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()
	now := time.Now()
	for tokenID, expiration := range tb.blacklist {
		if now.After(expiration) {
			delete(tb.blacklist, tokenID)
		}
	}
}

// TokenCache caches tokens
type TokenCache struct {
	cache *Cache
}

// NewTokenCache creates a new TokenCache
func NewTokenCache() *TokenCache {
	return &TokenCache{
		cache: NewCache(),
	}
}

// Set sets a token in the cache
func (tc *TokenCache) Set(token string, claims map[string]interface{}, expiration time.Duration) {
	token = "t-" + token
	tc.cache.Set(token, claims, expiration)
}

// Get retrieves a token from the cache
func (tc *TokenCache) Get(token string) (map[string]interface{}, bool) {
	token = "t-" + token
	value, found := tc.cache.Get(token)
	if !found {
		return nil, false
	}
	claims, ok := value.(map[string]interface{})
	return claims, ok
}

// Delete removes a token from the cache
func (tc *TokenCache) Delete(token string) {
	token = "t-" + token
	tc.cache.Delete(token)
}

// Cleanup cleans up expired tokens from the cache
func (tc *TokenCache) Cleanup() {
	tc.cache.Cleanup()
}

// exchangeCodeForToken exchanges the authorization code for tokens
func (t *TraefikOidc) exchangeCodeForToken(code string, redirectURL string) (*TokenResponse, error) {
	ctx := context.Background()
	tokenResponse, err := t.exchangeTokens(ctx, "authorization_code", code, redirectURL)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	return tokenResponse, nil
}

// createStringMap creates a map from a slice of strings
func createStringMap(keys []string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, key := range keys {
		result[key] = struct{}{}
	}
	return result
}

// handleLogout handles the logout request
func (t *TraefikOidc) handleLogout(rw http.ResponseWriter, req *http.Request) {
	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Error getting session: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	// Get the access token before clearing session
	accessToken := session.GetAccessToken()

	// Clear all session data
	if err := session.Clear(req, rw); err != nil {
		t.logger.Errorf("Error clearing session: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	// Get the base URL for redirects
	host := t.determineHost(req)
	scheme := t.determineScheme(req)
	baseURL := fmt.Sprintf("%s://%s", scheme, host)

	// Determine post logout redirect URI
	postLogoutRedirectURI := t.postLogoutRedirectURI
	if postLogoutRedirectURI == "" {
		postLogoutRedirectURI = fmt.Sprintf("%s/", baseURL)
	} else if !strings.HasPrefix(postLogoutRedirectURI, "http") {
		postLogoutRedirectURI = fmt.Sprintf("%s%s", baseURL, postLogoutRedirectURI)
	}

	// If we have an end session endpoint and an access token, use OIDC end session
	if t.endSessionURL != "" && accessToken != "" {
		logoutURL, err := BuildLogoutURL(t.endSessionURL, accessToken, postLogoutRedirectURI)
		if err != nil {
			t.logger.Errorf("Failed to build logout URL: %v", err)
			http.Error(rw, "Logout error", http.StatusInternalServerError)
			return
		}
		http.Redirect(rw, req, logoutURL, http.StatusFound)
		return
	}

	// Otherwise, redirect to post logout URI
	http.Redirect(rw, req, postLogoutRedirectURI, http.StatusFound)
}

// BuildLogoutURL constructs the OIDC end session URL
func BuildLogoutURL(endSessionURL, idToken, postLogoutRedirectURI string) (string, error) {
	u, err := url.Parse(endSessionURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse end session URL: %w", err)
	}

	q := u.Query()
	q.Set("id_token_hint", idToken)
	if postLogoutRedirectURI != "" {
		// Ensure postLogoutRedirectURI is properly URL encoded
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}
