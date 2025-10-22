// Package token provides token management functionality for OIDC authentication.
package token

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Refresher handles token refresh operations
type Refresher struct {
	clientID       string
	clientSecret   string
	tokenURL       string
	httpClient     *http.Client
	logger         LoggerInterface
	metrics        MetricsInterface
	sessionManager SessionManagerInterface
	tokenCache     CacheInterface
	verifier       TokenVerifier
}

// NewRefresher creates a new token refresher
func NewRefresher(clientID, clientSecret, tokenURL string, httpClient *http.Client, logger LoggerInterface, metrics MetricsInterface, sessionManager SessionManagerInterface, tokenCache CacheInterface, verifier TokenVerifier) *Refresher {
	return &Refresher{
		clientID:       clientID,
		clientSecret:   clientSecret,
		tokenURL:       tokenURL,
		httpClient:     httpClient,
		logger:         logger,
		metrics:        metrics,
		sessionManager: sessionManager,
		tokenCache:     tokenCache,
		verifier:       verifier,
	}
}

// RefreshToken attempts to refresh expired tokens using the refresh token.
// Returns true if refresh was successful or not needed, false if refresh failed and session should be terminated.
func (r *Refresher) RefreshToken(rw http.ResponseWriter, req *http.Request, session SessionDataInterface) bool {
	if session == nil {
		r.logger.ErrorLogf("RefreshToken: Session is nil")
		return false
	}

	refreshToken := session.GetRefreshToken()
	if refreshToken == "" {
		r.logger.Logf("No refresh token available, cannot refresh")
		return false
	}

	r.logger.Logf("Attempting to refresh expired tokens")
	tokenResp, err := r.GetNewTokenWithRefreshToken(refreshToken)
	if err != nil {
		r.logger.ErrorLogf("Failed to refresh tokens: %v", err)
		r.metrics.RecordTokenRefreshError()
		return false
	}

	// Parse expiry from expires_in
	var idTokenExpiry, accessTokenExpiry time.Time
	if tokenResp.ExpiresIn > 0 {
		expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
		idTokenExpiry = expiry
		accessTokenExpiry = expiry
	}

	// Update session with new tokens
	if tokenResp.IDToken != "" && tokenResp.AccessToken != "" {
		session.SetTokens(
			tokenResp.IDToken,
			tokenResp.AccessToken,
			tokenResp.RefreshToken,
			idTokenExpiry,
			accessTokenExpiry,
		)
	} else if tokenResp.IDToken != "" {
		session.SetIDToken(tokenResp.IDToken, idTokenExpiry)
		if tokenResp.RefreshToken != "" {
			session.SetRefreshToken(tokenResp.RefreshToken)
		}
	} else if tokenResp.AccessToken != "" {
		session.SetAccessToken(tokenResp.AccessToken, accessTokenExpiry)
		if tokenResp.RefreshToken != "" {
			session.SetRefreshToken(tokenResp.RefreshToken)
		}
	}

	// Clear old tokens from cache
	if oldIDToken := session.GetIDToken(); oldIDToken != "" {
		r.tokenCache.Delete(oldIDToken)
	}
	if oldAccessToken := session.GetAccessToken(); oldAccessToken != "" {
		r.tokenCache.Delete(oldAccessToken)
	}

	// Verify and cache new tokens
	if tokenResp.IDToken != "" {
		if err := r.verifier.VerifyToken(tokenResp.IDToken); err != nil {
			r.logger.ErrorLogf("Failed to verify refreshed ID token: %v", err)
			return false
		}
	}
	if tokenResp.AccessToken != "" {
		if err := r.verifier.VerifyToken(tokenResp.AccessToken); err != nil {
			r.logger.ErrorLogf("Failed to verify refreshed access token: %v", err)
			return false
		}
	}

	// Save updated session
	if err := session.SaveToCache(); err != nil {
		r.logger.ErrorLogf("Failed to save refreshed session: %v", err)
		return false
	}

	r.metrics.RecordTokenRefresh()
	r.logger.Logf("Successfully refreshed tokens")
	return true
}

// GetNewTokenWithRefreshToken exchanges a refresh token for new tokens
func (r *Refresher) GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	return r.exchangeToken("refresh_token", refreshToken, "", "")
}

// exchangeToken performs the actual token exchange with the provider
func (r *Refresher) exchangeToken(grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", r.clientID)
	data.Set("client_secret", r.clientSecret)
	data.Set("grant_type", grantType)

	switch grantType {
	case "authorization_code":
		data.Set("code", codeOrToken)
		if redirectURL != "" {
			data.Set("redirect_uri", redirectURL)
		}
		if codeVerifier != "" {
			data.Set("code_verifier", codeVerifier)
		}
	case "refresh_token":
		data.Set("refresh_token", codeOrToken)
	default:
		return nil, fmt.Errorf("unsupported grant type: %s", grantType)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, r.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}
