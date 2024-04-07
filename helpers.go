package traefikoidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func generateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce")
	}
	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

func assembleRedirectURL(scheme, host, path string) string {
	if scheme == "" {
		scheme = "http" // Default to http if scheme is empty
	}
	return scheme + "://" + host + path
}

func (t *TraefikOidc) exchangeCodeForToken(ctx context.Context, code string, redirectURL string) (map[string]interface{}, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", t.clientID)
	data.Set("client_secret", t.clientSecret)
	data.Set("redirect_uri", redirectURL) // Use the full redirect URL

	// infoLogger.Printf("Exchanging code for token with redirect_uri: %s", redirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", t.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// infoLogger.Printf("Token response: %+v", result)

	return result, nil
}

func (t *TraefikOidc) handleCallback(rw http.ResponseWriter, req *http.Request) (bool, string) {
	ctx := req.Context()
	session, err := t.store.Get(req, cookie_name)
	if err != nil {
		// infoLogger.Printf("Error getting session: %v", err)
		http.Error(rw, "Session error", http.StatusInternalServerError)
		return false, ""
	}

	// infoLogger.Printf("Session values: %+v", session.Values)

	callbackState := req.URL.Query().Get("state")
	sessionState, ok := session.Values["csrf"].(string)
	// infoLogger.Printf("Callback state: %s, Session state: %s, Match: %v", callbackState, sessionState, ok && callbackState == sessionState)

	if !ok || callbackState != sessionState {
		// infoLogger.Printf("Invalid state parameter: callback=%s, session=%s", callbackState, sessionState)
		http.Error(rw, "Invalid state parameter", http.StatusBadRequest)
		return false, ""
	}

	code := req.URL.Query().Get("code")
	redirectURL := assembleRedirectURL(req.URL.Scheme, req.Host, t.redirURLPath)
	oauth2Token, err := t.exchangeCodeForToken(ctx, code, redirectURL)
	if err != nil {
		// infoLogger.Printf("Failed to exchange token: %v", err)
		http.Error(rw, "Failed to exchange token", http.StatusInternalServerError)
		return false, ""
	}

	rawIDToken, ok := oauth2Token["id_token"].(string)
	if !ok {
		// infoLogger.Printf("No id_token field in oauth2 token")
		http.Error(rw, "No id_token field in oauth2 token", http.StatusInternalServerError)
		return false, ""
	}

	if err := t.verifyToken(rawIDToken); err != nil {
		// infoLogger.Printf("Token verification failed: %v", err)
		http.Error(rw, "Failed to verify token", http.StatusUnauthorized)
		return false, ""
	}
	// infoLogger.Printf("Token verification successful")

	claims, err := extractClaims(rawIDToken)
	if err != nil {
		// infoLogger.Printf("Failed to extract claims: %v", err)
		http.Error(rw, "Failed to extract claims", http.StatusInternalServerError)
		return false, ""
	}

	email, _ := claims["email"].(string)

	session.Values["authenticated"] = true
	session.Values["id_token"] = rawIDToken
	session.Values["email"] = email
	if err := session.Save(req, rw); err != nil {
		// infoLogger.Printf("Failed to save session: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return false, ""
	}

	// infoLogger.Printf("User %s authenticated\n", email)
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
		return nil, errors.New("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func verifyToken(token string, publicKey []byte) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	payloadJson, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	err = json.Unmarshal(payloadJson, &claims)
	if err != nil {
		return nil, err
	}

	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, errors.New("token expired")
		}
	}

	// Placeholder for signature verification
	// err = verifySignature(parts[0]+"."+parts[1], parts[2], publicKey)
	// if err != nil {
	//     return nil, err
	// }

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
