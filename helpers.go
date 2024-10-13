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

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

// generateNonce generates a random nonce
func generateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("could not generate nonce: %w", err)
	}
	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

// buildFullURL constructs a full URL from scheme, host, and path
func buildFullURL(scheme, host, path string) string {
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

// exchangeTokens exchanges a code or refresh token for tokens
func (t *TraefikOidc) exchangeTokens(ctx context.Context, grantType, codeOrToken, redirectURL string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {grantType},
		"client_id":     {t.clientID},
		"client_secret": {t.clientSecret},
	}

	switch grantType {
	case "authorization_code":
		data.Set("code", codeOrToken)
		data.Set("redirect_uri", redirectURL)
	case "refresh_token":
		data.Set("refresh_token", codeOrToken)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.tokenURL, strings.NewReader(data.Encode()))
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

// handleLogout handles the user logout
func (t *TraefikOidc) handleLogout(rw http.ResponseWriter, req *http.Request) {
	session, err := t.store.Get(req, cookieName)
	t.logger.Debugf("Logging out user")
	if err != nil {
		handleError(rw, "Session error", http.StatusInternalServerError, t.logger)
		return
	}

	// Revoke tokens if available
	for _, tokenType := range []string{"refresh_token", "access_token"} {
		if token, ok := session.Values[tokenType].(string); ok && token != "" {
			if err := t.RevokeTokenWithProvider(token, tokenType); err != nil {
				t.logger.Errorf("Failed to revoke %s: %v", tokenType, err)
			}
			t.RevokeToken(token)
		}
		delete(session.Values, tokenType)
	}

	// Remove other session values
	delete(session.Values, "id_token")
	delete(session.Values, "authenticated")

	// Set session options to delete the session
	session.Options = &sessions.Options{MaxAge: -1, Path: "/", HttpOnly: true, Secure: true}

	if err := session.Save(req, rw); err != nil {
		handleError(rw, "Failed to save session", http.StatusInternalServerError, t.logger)
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("Logged out successfully"))
}

// handleExpiredToken handles the case when a token has expired
func (t *TraefikOidc) handleExpiredToken(rw http.ResponseWriter, req *http.Request, session *sessions.Session) {
	if session == nil {
		t.logger.Error("Session is nil in handleExpiredToken")
		http.Error(rw, "Internal server error", http.StatusInternalServerError)
		return
	}
	// Clear the existing session
	for k := range session.Values {
		delete(session.Values, k)
	}

	// Set new values
	session.Values["csrf"] = uuid.New().String()
	session.Values["incoming_path"] = req.URL.Path
	session.Values["nonce"], _ = generateNonce()
	session.Options = &sessions.Options{MaxAge: 3600, Path: "/", HttpOnly: true, Secure: true}

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session: %v", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	t.initiateAuthenticationFunc(rw, req, session, t.redirectURL)
}

// handleCallback handles the callback from the OIDC provider
func (t *TraefikOidc) handleCallback(rw http.ResponseWriter, req *http.Request) {
	session, err := t.store.Get(req, cookieName)
	if err != nil {
		t.logger.Errorf("Session error: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Handling callback, URL: %s", req.URL.String())

	if errParam := req.URL.Query().Get("error"); errParam != "" {
		errorDescription := req.URL.Query().Get("error_description")
		t.logger.Errorf("Authentication error: %s - %s", errParam, errorDescription)
		http.Error(rw, fmt.Sprintf("Authentication error: %s", errorDescription), http.StatusBadRequest)
		return
	}

	state := req.URL.Query().Get("state")
	csrfToken, ok := session.Values["csrf"].(string)
	if !ok || state == "" || csrfToken == "" || state != csrfToken {
		t.logger.Error("Invalid state parameter or CSRF token")
		http.Error(rw, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	code := req.URL.Query().Get("code")
	if code == "" {
		t.logger.Error("No code in callback")
		http.Error(rw, "No code in callback", http.StatusBadRequest)
		return
	}

	tokenResponse, err := t.exchangeCodeForTokenFunc(code)
	if err != nil {
		t.logger.Errorf("Failed to exchange code for token: %v", err)
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	idToken := tokenResponse.IDToken
	if idToken == "" {
		t.logger.Error("No id_token in token response")
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	if err := t.verifyToken(idToken); err != nil {
		t.logger.Errorf("Failed to verify id_token: %v", err)
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	claims, err := t.extractClaimsFunc(idToken)
	if err != nil {
		t.logger.Errorf("Failed to extract claims: %v", err)
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	nonceClaim, ok := claims["nonce"].(string)
	sessionNonce, ok2 := session.Values["nonce"].(string)
	if !ok || !ok2 || nonceClaim == "" || sessionNonce == "" || nonceClaim != sessionNonce {
		t.logger.Error("Invalid nonce")
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	email, _ := claims["email"].(string)
	if email == "" || !t.isAllowedDomain(email) {
		t.logger.Errorf("Invalid or disallowed email: %s", email)
		http.Error(rw, "Authentication failed: Invalid or disallowed email", http.StatusForbidden)
		return
	}

	session.Values["authenticated"] = true
	session.Values["email"] = email
	session.Values["id_token"] = idToken
	session.Values["refresh_token"] = tokenResponse.RefreshToken
	session.Options = &sessions.Options{MaxAge: 3600, Path: "/", HttpOnly: true, Secure: true}

	delete(session.Values, "csrf")
	delete(session.Values, "nonce")

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Authentication successful. User email: %s", email)

	redirectPath := "/"
	if path, ok := session.Values["incoming_path"].(string); ok && path != t.redirURLPath {
		t.logger.Debugf("Redirecting to incoming path from original request: %s", path)
		redirectPath = path
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
	blacklist sync.Map
}

// NewTokenBlacklist creates a new TokenBlacklist
func NewTokenBlacklist() *TokenBlacklist {
	return &TokenBlacklist{}
}
func (tb *TokenBlacklist) Add(token string, expiration time.Time) {
	tb.blacklist.Store(token, expiration)
}

func (tb *TokenBlacklist) IsBlacklisted(token string) bool {
	if exp, ok := tb.blacklist.Load(token); ok {
		return time.Now().Before(exp.(time.Time))
	}
	return false
}

func (tb *TokenBlacklist) Cleanup() {
	now := time.Now()
	tb.blacklist.Range(func(key, value interface{}) bool {
		if now.After(value.(time.Time)) {
			tb.blacklist.Delete(key)
		}
		return true
	})
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
	tc.cache.Set("t-"+token, claims, expiration)
}

// Get retrieves a token from the cache
func (tc *TokenCache) Get(token string) (map[string]interface{}, bool) {
	value, found := tc.cache.Get("t-" + token)
	if !found {
		return nil, false
	}
	claims, ok := value.(map[string]interface{})
	return claims, ok
}

// Delete removes a token from the cache
func (tc *TokenCache) Delete(token string) {
	tc.cache.Delete("t-" + token)
}

// Cleanup cleans up expired tokens from the cache
func (tc *TokenCache) Cleanup() {
	tc.cache.Cleanup()
}

// exchangeCodeForToken exchanges the authorization code for tokens
func (t *TraefikOidc) exchangeCodeForToken(code string) (*TokenResponse, error) {
	ctx := context.Background()
	tokenResponse, err := t.exchangeTokens(ctx, "authorization_code", code, t.redirectURL)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	return tokenResponse, nil
}

// createStringMap creates a map from a slice of strings
func createStringMap(keys []string) map[string]struct{} {
	result := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		result[key] = struct{}{}
	}
	return result
}
