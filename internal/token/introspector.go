// Package token provides token management functionality for OIDC authentication.
package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Introspector handles token introspection operations
type Introspector struct {
	clientID           string
	clientSecret       string
	introspectionURL   string
	httpClient         *http.Client
	logger             LoggerInterface
	groupsClaimPath    []string
	rolesClaimPath     []string
	extractClaimsRegex string
}

// NewIntrospector creates a new token introspector
func NewIntrospector(clientID, clientSecret, introspectionURL string, httpClient *http.Client, logger LoggerInterface, groupsClaimPath, rolesClaimPath []string, extractClaimsRegex string) *Introspector {
	return &Introspector{
		clientID:           clientID,
		clientSecret:       clientSecret,
		introspectionURL:   introspectionURL,
		httpClient:         httpClient,
		logger:             logger,
		groupsClaimPath:    groupsClaimPath,
		rolesClaimPath:     rolesClaimPath,
		extractClaimsRegex: extractClaimsRegex,
	}
}

// IntrospectToken performs token introspection with the OIDC provider
func (i *Introspector) IntrospectToken(token string, tokenTypeHint string) (*IntrospectionResponse, error) {
	if i.introspectionURL == "" {
		return nil, fmt.Errorf("introspection endpoint not configured")
	}

	data := url.Values{}
	data.Set("token", token)
	if tokenTypeHint != "" {
		data.Set("token_type_hint", tokenTypeHint)
	}
	data.Set("client_id", i.clientID)
	data.Set("client_secret", i.clientSecret)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, i.introspectionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := i.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read introspection response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection failed with status %d: %s", resp.StatusCode, string(body))
	}

	var introspectResp IntrospectionResponse
	if err := json.Unmarshal(body, &introspectResp); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	// Parse any extra fields
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err == nil {
		introspectResp.Extra = make(map[string]interface{})
		for k, v := range raw {
			switch k {
			case "active", "scope", "client_id", "username", "token_type",
				"exp", "iat", "nbf", "sub", "aud", "iss", "jti":
				// Skip standard fields
			default:
				introspectResp.Extra[k] = v
			}
		}
	}

	return &introspectResp, nil
}

// ExtractGroupsAndRoles extracts groups and roles from an ID token
func (i *Introspector) ExtractGroupsAndRoles(idToken string) ([]string, []string, error) {
	jwt, err := parseJWT(idToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ID token: %w", err)
	}

	groups := i.extractClaimValues(jwt.Claims, i.groupsClaimPath)
	roles := i.extractClaimValues(jwt.Claims, i.rolesClaimPath)

	i.logger.Logf("Extracted %d groups and %d roles from ID token", len(groups), len(roles))
	return groups, roles, nil
}

// DetectTokenType analyzes a token and determines its type
func (i *Introspector) DetectTokenType(token string) (string, error) {
	jwt, err := parseJWT(token)
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	// Check for ID token characteristics
	if aud, ok := jwt.Claims["aud"]; ok {
		switch v := aud.(type) {
		case string:
			if v == i.clientID {
				return "id_token", nil
			}
		case []interface{}:
			for _, a := range v {
				if str, ok := a.(string); ok && str == i.clientID {
					return "id_token", nil
				}
			}
		}
	}

	// Check for access token characteristics
	if scope, ok := jwt.Claims["scope"]; ok {
		if _, isString := scope.(string); isString {
			return "access_token", nil
		}
	}

	// Check token_use claim (AWS Cognito specific)
	if tokenUse, ok := jwt.Claims["token_use"]; ok {
		if use, isString := tokenUse.(string); isString {
			switch use {
			case "id":
				return "id_token", nil
			case "access":
				return "access_token", nil
			}
		}
	}

	// Check typ header
	if typ, ok := jwt.Header["typ"]; ok {
		if typStr, isString := typ.(string); isString {
			switch strings.ToLower(typStr) {
			case "jwt", "at+jwt":
				return "access_token", nil
			case "id+jwt":
				return "id_token", nil
			}
		}
	}

	return "unknown", nil
}

// extractClaimValues extracts claim values from JWT claims using a path
func (i *Introspector) extractClaimValues(claims map[string]interface{}, claimPath []string) []string {
	if len(claimPath) == 0 {
		return nil
	}

	var result []string
	current := claims

	for idx, key := range claimPath {
		if idx == len(claimPath)-1 {
			// Last key - extract the values
			if val, exists := current[key]; exists {
				result = i.extractStringSlice(val)
			}
		} else {
			// Navigate deeper
			if next, ok := current[key].(map[string]interface{}); ok {
				current = next
			} else {
				break
			}
		}
	}

	return result
}

// extractStringSlice converts various types to string slice
func (i *Introspector) extractStringSlice(val interface{}) []string {
	switch v := val.(type) {
	case []interface{}:
		var result []string
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return v
	case string:
		if v != "" {
			// Handle comma-separated or space-separated values
			if strings.Contains(v, ",") {
				return strings.Split(v, ",")
			}
			return []string{v}
		}
	}
	return nil
}

// parseJWT parses a JWT token without verification
func parseJWT(token string) (*JWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	header, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	claims, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	return &JWT{
		Header: header,
		Claims: claims,
	}, nil
}

// decodeSegment decodes a base64url encoded JWT segment
func decodeSegment(seg string) (map[string]interface{}, error) {
	// Add padding if necessary
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	decoded, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		return nil, fmt.Errorf("failed to decode segment: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(decoded, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal segment: %w", err)
	}

	return result, nil
}
