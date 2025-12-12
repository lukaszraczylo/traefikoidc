// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file implements OAuth 2.0 Token Introspection (RFC 7662) for opaque token validation.
package traefikoidc

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

// IntrospectionResponse represents the response from an OAuth 2.0 token introspection endpoint.
// Per RFC 7662, this contains information about the token's validity and properties.
type IntrospectionResponse struct {
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Active    bool   `json:"active"`
}

// introspectToken performs OAuth 2.0 Token Introspection (RFC 7662) for an opaque token.
// It queries the provider's introspection endpoint to determine token validity and properties.
// Results are cached to minimize repeated introspection requests.
//
// Parameters:
//   - token: The opaque access token to introspect
//
// Returns:
//   - *IntrospectionResponse: The introspection result
//   - error: Any error that occurred during introspection
func (t *TraefikOidc) introspectToken(token string) (*IntrospectionResponse, error) {
	// Check cache first
	if t.introspectionCache != nil {
		if cached, found := t.introspectionCache.Get(token); found {
			if response, ok := cached.(*IntrospectionResponse); ok {
				t.logger.Debugf("Using cached introspection result for token")
				return response, nil
			}
		}
	}

	// Get introspection URL
	t.metadataMu.RLock()
	introspectionURL := t.introspectionURL
	t.metadataMu.RUnlock()

	if introspectionURL == "" {
		return nil, fmt.Errorf("introspection endpoint not available from provider")
	}

	// Prepare introspection request per RFC 7662 Section 2.1
	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", "access_token") // Hint that it's an access token

	// Create HTTP request
	req, err := http.NewRequestWithContext(context.Background(), "POST", introspectionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}

	// Set required headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Authenticate using client credentials (per RFC 7662 Section 2.1)
	// The introspection endpoint requires authentication
	req.SetBasicAuth(t.clientID, t.clientSecret)

	// Send request with circuit breaker if available
	var resp *http.Response
	if t.errorRecoveryManager != nil {
		t.metadataMu.RLock()
		serviceName := fmt.Sprintf("token-introspection-%s", t.issuerURL)
		t.metadataMu.RUnlock()

		err = t.errorRecoveryManager.ExecuteWithRecovery(context.Background(), serviceName, func() error {
			var reqErr error
			resp, reqErr = t.httpClient.Do(req) //nolint:bodyclose // Body is closed in defer after error check
			if reqErr != nil && resp != nil && resp.Body != nil {
				_ = resp.Body.Close() // Safe to ignore: closing body on error
			}
			return reqErr
		})
	} else {
		resp, err = t.httpClient.Do(req)
	}

	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close() // Safe to ignore: closing body on error
		}
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body) // Safe to ignore: draining body on defer
			_ = resp.Body.Close()                 // Safe to ignore: closing body on defer
		}
	}()

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		limitReader := io.LimitReader(resp.Body, 1024*10)
		body, _ := io.ReadAll(limitReader) // Safe to ignore: reading error body for diagnostics
		return nil, fmt.Errorf("introspection endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response per RFC 7662 Section 2.2
	var introspectionResp IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspectionResp); err != nil {
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	// Cache the result
	if t.introspectionCache != nil {
		// Cache for a short duration or until token expiry (whichever is shorter)
		cacheDuration := 5 * time.Minute
		if introspectionResp.Exp > 0 {
			expTime := time.Unix(introspectionResp.Exp, 0)
			untilExp := time.Until(expTime)
			if untilExp > 0 && untilExp < cacheDuration {
				cacheDuration = untilExp
			}
		}
		t.introspectionCache.Set(token, &introspectionResp, cacheDuration)
		t.logger.Debugf("Cached introspection result for %v", cacheDuration)
	}

	return &introspectionResp, nil
}

// validateOpaqueToken validates an opaque access token using token introspection.
// It checks if the token is active, not expired, and has the correct audience if specified.
//
// Parameters:
//   - token: The opaque access token to validate
//
// Returns:
//   - error: Validation error if token is invalid, nil if valid
func (t *TraefikOidc) validateOpaqueToken(token string) error {
	// Check if opaque tokens are allowed
	if !t.allowOpaqueTokens {
		return fmt.Errorf("opaque tokens are not enabled (set allowOpaqueTokens to true)")
	}

	// Check if introspection is required but not available
	t.metadataMu.RLock()
	introspectionURL := t.introspectionURL
	t.metadataMu.RUnlock()

	if introspectionURL == "" {
		if t.requireTokenIntrospection {
			return fmt.Errorf("token introspection required but endpoint not available")
		}
		// Allow fallback to ID token validation
		t.logger.Debugf("Introspection endpoint not available, will rely on ID token validation")
		return nil
	}

	// Perform introspection
	resp, err := t.introspectToken(token)
	if err != nil {
		return fmt.Errorf("token introspection failed: %w", err)
	}

	// Check if token is active (per RFC 7662 Section 2.2)
	if !resp.Active {
		return fmt.Errorf("token is not active (revoked or expired)")
	}

	// Validate expiration if present
	if resp.Exp > 0 {
		expTime := time.Unix(resp.Exp, 0)
		if time.Now().After(expTime) {
			return fmt.Errorf("token has expired")
		}
	}

	// Validate not-before if present
	if resp.Nbf > 0 {
		nbfTime := time.Unix(resp.Nbf, 0)
		if time.Now().Before(nbfTime) {
			return fmt.Errorf("token not yet valid (nbf)")
		}
	}

	// Validate audience if configured
	// Note: For opaque tokens, audience validation via introspection may be limited
	// depending on what the introspection endpoint returns
	if t.audience != "" && t.audience != t.clientID && resp.Aud != "" {
		if resp.Aud != t.audience {
			return fmt.Errorf("invalid audience: expected %s, got %s", t.audience, resp.Aud)
		}
	}

	t.logger.Debugf("Opaque token validation successful via introspection")
	return nil
}
