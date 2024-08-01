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

	response := &TokenResponse{
		IDToken:     result["id_token"].(string),
		AccessToken: result["access_token"].(string),
		ExpiresIn:   int(result["expires_in"].(float64)),
		TokenType:   result["token_type"].(string),
	}

	// The refresh token might not be returned if it hasn't changed
	if newRefreshToken, ok := result["refresh_token"].(string); ok {
		response.RefreshToken = newRefreshToken
	} else {
		response.RefreshToken = refreshToken
	}

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
		t.RevokeToken(idToken)
	}

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
	session.Values = make(map[interface{}]interface{})
	err := session.Save(req, rw)
	if err != nil {
		t.logger.Errorf("Failed to clear session: %v", err)
	}
	t.initiateAuthentication(rw, req, session, t.redirectURL)
}

func (t *TraefikOidc) handleCallback(rw http.ResponseWriter, req *http.Request) (bool, string) {
	session, err := t.store.Get(req, cookieName)
	if err != nil {
		handleError(rw, "Session error", http.StatusInternalServerError, t.logger)
		return false, ""
	}

	callbackState := req.URL.Query().Get("state")
	sessionState, ok := session.Values["csrf"].(string)
	if !ok || callbackState != sessionState {
		handleError(rw, "Invalid state parameter", http.StatusBadRequest, t.logger)
		return false, ""
	}

	code := req.URL.Query().Get("code")
	redirectURL := buildFullURL(t.scheme, req.Host, t.redirURLPath)

	oauth2Token, err := t.exchangeTokens(req.Context(), "authorization_code", code, redirectURL)
	if err != nil {
		handleError(rw, "Failed to exchange token", http.StatusUnauthorized, t.logger)
		return false, ""
	}

	rawIDToken, ok := oauth2Token["id_token"].(string)
	if !ok {
		handleError(rw, "No id_token field in oauth2 token", http.StatusUnauthorized, t.logger)
		return false, ""
	}

	if err := t.verifyToken(rawIDToken); err != nil {
		handleError(rw, "Failed to verify token", http.StatusUnauthorized, t.logger)
		return false, ""
	}

	claims, err := extractClaims(rawIDToken)
	if err != nil {
		handleError(rw, "Failed to extract claims", http.StatusInternalServerError, t.logger)
		return false, ""
	}

	email, _ := claims["email"].(string)

	session.Values["authenticated"] = true
	session.Values["id_token"] = rawIDToken
	session.Values["refresh_token"] = oauth2Token["refresh_token"]
	session.Values["email"] = email
	if err := session.Save(req, rw); err != nil {
		handleError(rw, "Failed to save session", http.StatusInternalServerError, t.logger)
		return false, ""
	}

	originalPath, ok := session.Values["incoming_path"].(string)
	if !ok {
		originalPath = "/"
	}
	delete(session.Values, "incoming_path")

	return true, originalPath
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

type UsedTokens struct {
	tokens map[string]bool
	mutex  sync.RWMutex
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
	cache map[string]*TokenInfo
	mutex sync.RWMutex
}

type TokenInfo struct {
	Token     string
	ExpiresAt time.Time
}

func NewTokenCache() *TokenCache {
	return &TokenCache{
		cache: make(map[string]*TokenInfo),
	}
}

func (tc *TokenCache) Set(token string, expiresAt time.Time) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.cache[token] = &TokenInfo{Token: token, ExpiresAt: expiresAt}
}

func (tc *TokenCache) Get(token string) (*TokenInfo, bool) {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	info, exists := tc.cache[token]
	if exists && time.Now().Before(info.ExpiresAt) {
		return info, true
	}
	return nil, false
}

func (tc *TokenCache) Delete(token string) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	delete(tc.cache, token)
}

func (tc *TokenCache) Cleanup() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	now := time.Now()
	for token, info := range tc.cache {
		if now.After(info.ExpiresAt) {
			delete(tc.cache, token)
		}
	}
}
