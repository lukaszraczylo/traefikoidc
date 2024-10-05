package traefikoidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

func generateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce: %w", err)
	}
	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

func buildFullURL(scheme, host, path string) string {
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

func (t *TraefikOidc) exchangeTokens(ctx context.Context, grantType, codeOrToken, redirectURL string) (map[string]interface{}, error) {
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

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return result, nil
}

type TokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (t *TraefikOidc) getNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	ctx := context.Background()
	result, err := t.exchangeTokens(ctx, "refresh_token", refreshToken, "")
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	newAccessToken, ok := result["access_token"].(string)
	if !ok || newAccessToken == "" {
		return nil, fmt.Errorf("no access_token field in token response")
	}

	rawIDToken, ok := result["id_token"].(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("no id_token field in token response")
	}

	newRefreshToken, ok := result["refresh_token"].(string)
	if !ok || newRefreshToken == "" {
		return nil, fmt.Errorf("no refresh_token field in token response")
	}

	response := &TokenResponse{
		IDToken:     rawIDToken,
		AccessToken: newAccessToken,
		ExpiresIn:   int(result["expires_in"].(float64)),
		TokenType:   result["token_type"].(string),
	}

	// The refresh token might not be returned if it hasn't changed
	if newRefreshToken != refreshToken {
		response.RefreshToken = newRefreshToken
	} else {
		response.RefreshToken = refreshToken
	}

	t.logger.Debug("Token response: %+v", response)

	return response, nil
}

func (t *TraefikOidc) handleLogout(rw http.ResponseWriter, req *http.Request) {
	session, err := t.store.Get(req, cookieName)
	t.logger.Debugf("Logging out user")
	if err != nil {
		handleError(rw, "Session error", http.StatusInternalServerError, t.logger)
		return
	}

	if idToken, ok := session.Values["id_token"].(string); ok {
		err := t.RevokeTokenWithProvider(idToken)
		if err != nil {
			handleError(rw, "Failed to revoke token", http.StatusInternalServerError, t.logger)
			return
		}
		t.RevokeToken(idToken)
	}

	session.Options = defaultSessionOptions
	// Clear the session
	session.Options.MaxAge = -1
	session.Values = make(map[interface{}]interface{})
	err = session.Save(req, rw)
	if err != nil {
		handleError(rw, "Failed to save session", http.StatusInternalServerError, t.logger)
		return
	}

	http.Error(rw, "Logged out", http.StatusForbidden)
}

func (t *TraefikOidc) handleExpiredToken(rw http.ResponseWriter, req *http.Request, session *sessions.Session) {
	// Clear the existing session
	session.Options.MaxAge = -1
	for k := range session.Values {
		delete(session.Values, k)
	}

	// Set new values
	session.Values["csrf"] = uuid.New().String()
	session.Values["incoming_path"] = req.URL.Path
	session.Values["nonce"], _ = generateNonce()
	session.Options = defaultSessionOptions

	// Save the session before initiating authentication
	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session: %v", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Initiate a new authentication flow
	t.initiateAuthenticationFunc(rw, req, session, t.redirectURL)
}

func (t *TraefikOidc) handleCallback(rw http.ResponseWriter, req *http.Request) {
	session, err := t.store.Get(req, cookieName)
	if err != nil {
		t.logger.Errorf("Session error: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Handling callback, URL: %s", req.URL.String())

	code := req.URL.Query().Get("code")
	if code == "" {
		t.logger.Error("No code in callback")
		http.Error(rw, "No code in callback", http.StatusBadRequest)
		return
	}

	token, err := t.exchangeCodeForTokenFunc(code)
	if err != nil {
		t.logger.Errorf("Failed to exchange code for token: %v", err)
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	idToken, ok := token["id_token"].(string)
	if !ok || idToken == "" {
		t.logger.Error("No id_token in token response")
		http.Error(rw, "Authentication failed", http.StatusInternalServerError)
		return
	}

	claims, err := t.extractClaimsFunc(idToken)
	if err != nil {
		t.logger.Errorf("Failed to extract claims: %v", err)
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
	session.Options = defaultSessionOptions

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Authentication successful. User email: %s", email)
	http.Redirect(rw, req, func() string {
		if path, ok := session.Values["incoming_path"].(string); ok {
			t.logger.Debug("Redirecting to incoming path from original request: %s", path)
			return path
		}
		t.logger.Debug("Redirecting to root path as no incoming path found")
		return "/"
	}(), http.StatusFound)
}

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

type TokenBlacklist struct {
	blacklist map[string]time.Time
	mutex     sync.RWMutex
}

func NewTokenBlacklist() *TokenBlacklist {
	return &TokenBlacklist{
		blacklist: make(map[string]time.Time),
	}
}

func (tb *TokenBlacklist) Add(tokenID string, expiration time.Time) {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()
	tb.blacklist[tokenID] = expiration
}

func (tb *TokenBlacklist) IsBlacklisted(tokenID string) bool {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()
	expiration, exists := tb.blacklist[tokenID]
	return exists && time.Now().Before(expiration)
}

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

type TokenCache struct {
	cache *Cache
}

type TokenInfo struct {
	Token     string
	ExpiresAt time.Time
}

func NewTokenCache() *TokenCache {
	return &TokenCache{
		cache: NewCache(),
	}
}

func (tc *TokenCache) Set(token string, claims map[string]interface{}, expiration time.Duration) {
	token = "t-" + token
	tc.cache.Set(token, claims, expiration)
}

func (tc *TokenCache) Get(token string) (map[string]interface{}, bool) {
	token = "t-" + token
	value, found := tc.cache.Get(token)
	if !found {
		return nil, false
	}
	claims, ok := value.(map[string]interface{})
	return claims, ok
}

func (tc *TokenCache) Delete(token string) {
	token = "t-" + token
	tc.cache.Delete(token)
}

func (tc *TokenCache) Cleanup() {
	tc.cache.Cleanup()
}

func (t *TraefikOidc) exchangeCodeForToken(code string) (map[string]interface{}, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", t.clientID)
	data.Set("client_secret", t.clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", t.redirectURL)

	resp, err := t.httpClient.PostForm(t.tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %v", err)
	}

	return result, nil
}
