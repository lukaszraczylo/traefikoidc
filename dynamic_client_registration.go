// Package traefikoidc provides OIDC authentication middleware for Traefik
package traefikoidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ClientRegistrationResponse represents the response from a successful client registration (RFC 7591)
type ClientRegistrationResponse struct {
	// Required fields
	ClientID string `json:"client_id"`

	// Conditional - only for confidential clients
	ClientSecret string `json:"client_secret,omitempty"`

	// Optional - for managing registration
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`

	// Expiration
	ClientIDIssuedAt      int64 `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at,omitempty"`

	// Echo back of registered metadata
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	TOSURI                  string   `json:"tos_uri,omitempty"`
	JWKSURI                 string   `json:"jwks_uri,omitempty"`
	SubjectType             string   `json:"subject_type,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// ClientRegistrationError represents an error response from client registration (RFC 7591)
type ClientRegistrationError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// DynamicClientRegistrar handles OIDC Dynamic Client Registration (RFC 7591)
type DynamicClientRegistrar struct {
	httpClient  *http.Client
	logger      *Logger
	config      *DynamicClientRegistrationConfig
	providerURL string

	// Cached registration response
	mu                   sync.RWMutex
	registrationResponse *ClientRegistrationResponse
}

// NewDynamicClientRegistrar creates a new dynamic client registrar
func NewDynamicClientRegistrar(
	httpClient *http.Client,
	logger *Logger,
	dcrConfig *DynamicClientRegistrationConfig,
	providerURL string,
) *DynamicClientRegistrar {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
	}

	return &DynamicClientRegistrar{
		httpClient:  httpClient,
		logger:      logger,
		config:      dcrConfig,
		providerURL: providerURL,
	}
}

// RegisterClient performs dynamic client registration with the OIDC provider
// It first attempts to load existing credentials from a file if persistence is enabled,
// then registers a new client if no valid credentials exist.
func (r *DynamicClientRegistrar) RegisterClient(ctx context.Context, registrationEndpoint string) (*ClientRegistrationResponse, error) {
	if r.config == nil || !r.config.Enabled {
		return nil, fmt.Errorf("dynamic client registration is not enabled")
	}

	// Try to load existing credentials if persistence is enabled
	if r.config.PersistCredentials {
		if resp, err := r.loadCredentials(); err == nil && resp != nil {
			// Check if credentials are still valid (not expired)
			if r.areCredentialsValid(resp) {
				r.logger.Info("Loaded existing client credentials from file")
				r.mu.Lock()
				r.registrationResponse = resp
				r.mu.Unlock()
				return resp, nil
			}
			r.logger.Info("Existing credentials expired or invalid, registering new client")
		}
	}

	// Determine registration endpoint
	endpoint := registrationEndpoint
	if r.config.RegistrationEndpoint != "" {
		endpoint = r.config.RegistrationEndpoint
	}

	if endpoint == "" {
		return nil, fmt.Errorf("no registration endpoint available: provider does not support dynamic client registration or endpoint not configured")
	}

	// Validate the endpoint URL
	if !strings.HasPrefix(endpoint, "https://") {
		// Allow http only for localhost/development
		if !strings.HasPrefix(endpoint, "http://localhost") && !strings.HasPrefix(endpoint, "http://127.0.0.1") {
			return nil, fmt.Errorf("registration endpoint must use HTTPS for security")
		}
		r.logger.Infof("Warning: using insecure HTTP for registration endpoint (development only): %s", endpoint)
	}

	// Build registration request
	reqBody, err := r.buildRegistrationRequest()
	if err != nil {
		return nil, fmt.Errorf("failed to build registration request: %w", err)
	}

	r.logger.Debugf("Registering client at endpoint: %s", endpoint)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create registration request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add Initial Access Token if provided
	if r.config.InitialAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.config.InitialAccessToken)
	}

	// Execute request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read registration response: %w", err)
	}

	// Handle error responses
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var regError ClientRegistrationError
		if jsonErr := json.Unmarshal(body, &regError); jsonErr == nil && regError.Error != "" {
			return nil, fmt.Errorf("registration failed: %s - %s", regError.Error, regError.ErrorDescription)
		}
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse successful response
	var regResp ClientRegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	// Validate response
	if regResp.ClientID == "" {
		return nil, fmt.Errorf("registration response missing client_id")
	}

	r.logger.Infof("Successfully registered client with ID: %s", regResp.ClientID)

	// Cache the response
	r.mu.Lock()
	r.registrationResponse = &regResp
	r.mu.Unlock()

	// Persist credentials if enabled
	if r.config.PersistCredentials {
		if err := r.saveCredentials(&regResp); err != nil {
			r.logger.Errorf("Failed to persist client credentials: %v", err)
			// Don't fail registration if persistence fails
		}
	}

	return &regResp, nil
}

// buildRegistrationRequest creates the JSON request body for client registration
func (r *DynamicClientRegistrar) buildRegistrationRequest() ([]byte, error) {
	metadata := r.config.ClientMetadata
	if metadata == nil {
		metadata = &ClientRegistrationMetadata{}
	}

	// Build request object
	reqData := make(map[string]interface{})

	// Required: redirect_uris
	if len(metadata.RedirectURIs) > 0 {
		reqData["redirect_uris"] = metadata.RedirectURIs
	} else {
		return nil, fmt.Errorf("redirect_uris is required for client registration")
	}

	// Optional fields - only include if set
	if len(metadata.ResponseTypes) > 0 {
		reqData["response_types"] = metadata.ResponseTypes
	} else {
		// Default to authorization code flow
		reqData["response_types"] = []string{"code"}
	}

	if len(metadata.GrantTypes) > 0 {
		reqData["grant_types"] = metadata.GrantTypes
	} else {
		// Default grant types for authorization code flow
		reqData["grant_types"] = []string{"authorization_code", "refresh_token"}
	}

	if metadata.ApplicationType != "" {
		reqData["application_type"] = metadata.ApplicationType
	}

	if len(metadata.Contacts) > 0 {
		reqData["contacts"] = metadata.Contacts
	}

	if metadata.ClientName != "" {
		reqData["client_name"] = metadata.ClientName
	}

	if metadata.LogoURI != "" {
		reqData["logo_uri"] = metadata.LogoURI
	}

	if metadata.ClientURI != "" {
		reqData["client_uri"] = metadata.ClientURI
	}

	if metadata.PolicyURI != "" {
		reqData["policy_uri"] = metadata.PolicyURI
	}

	if metadata.TOSURI != "" {
		reqData["tos_uri"] = metadata.TOSURI
	}

	if metadata.JWKSURI != "" {
		reqData["jwks_uri"] = metadata.JWKSURI
	}

	if metadata.SubjectType != "" {
		reqData["subject_type"] = metadata.SubjectType
	}

	if metadata.TokenEndpointAuthMethod != "" {
		reqData["token_endpoint_auth_method"] = metadata.TokenEndpointAuthMethod
	} else {
		// Default to client_secret_basic for confidential clients
		reqData["token_endpoint_auth_method"] = "client_secret_basic"
	}

	if metadata.DefaultMaxAge > 0 {
		reqData["default_max_age"] = metadata.DefaultMaxAge
	}

	if metadata.RequireAuthTime {
		reqData["require_auth_time"] = metadata.RequireAuthTime
	}

	if len(metadata.DefaultACRValues) > 0 {
		reqData["default_acr_values"] = metadata.DefaultACRValues
	}

	if metadata.Scope != "" {
		reqData["scope"] = metadata.Scope
	}

	return json.Marshal(reqData)
}

// GetCachedResponse returns the cached registration response
func (r *DynamicClientRegistrar) GetCachedResponse() *ClientRegistrationResponse {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.registrationResponse
}

// areCredentialsValid checks if the cached credentials are still valid
func (r *DynamicClientRegistrar) areCredentialsValid(resp *ClientRegistrationResponse) bool {
	if resp == nil || resp.ClientID == "" {
		return false
	}

	// Check if secret has expired
	if resp.ClientSecretExpiresAt > 0 {
		expiresAt := time.Unix(resp.ClientSecretExpiresAt, 0)
		// Add 5 minute buffer before expiration
		if time.Now().Add(5 * time.Minute).After(expiresAt) {
			return false
		}
	}

	return true
}

// credentialsFilePath returns the path for storing credentials
func (r *DynamicClientRegistrar) credentialsFilePath() string {
	if r.config.CredentialsFile != "" {
		return r.config.CredentialsFile
	}
	return "/tmp/oidc-client-credentials.json"
}

// saveCredentials persists client credentials to a file
func (r *DynamicClientRegistrar) saveCredentials(resp *ClientRegistrationResponse) error {
	filePath := r.credentialsFilePath()

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Write with restrictive permissions (owner read/write only)
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials file: %w", err)
	}

	r.logger.Debugf("Saved client credentials to %s", filePath)
	return nil
}

// loadCredentials loads client credentials from a file
func (r *DynamicClientRegistrar) loadCredentials() (*ClientRegistrationResponse, error) {
	filePath := r.credentialsFilePath()

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No credentials file exists
		}
		return nil, fmt.Errorf("failed to read credentials file: %w", err)
	}

	var resp ClientRegistrationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse credentials file: %w", err)
	}

	return &resp, nil
}

// UpdateClientRegistration updates an existing client registration using RFC 7592
// This requires the registration_client_uri and registration_access_token from the original registration
func (r *DynamicClientRegistrar) UpdateClientRegistration(ctx context.Context) (*ClientRegistrationResponse, error) {
	r.mu.RLock()
	cachedResp := r.registrationResponse
	r.mu.RUnlock()

	if cachedResp == nil {
		return nil, fmt.Errorf("no existing registration to update")
	}

	if cachedResp.RegistrationClientURI == "" || cachedResp.RegistrationAccessToken == "" {
		return nil, fmt.Errorf("registration management not supported: missing registration_client_uri or registration_access_token")
	}

	// Build update request
	reqBody, err := r.buildRegistrationRequest()
	if err != nil {
		return nil, fmt.Errorf("failed to build update request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, cachedResp.RegistrationClientURI, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create update request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cachedResp.RegistrationAccessToken)

	// Execute request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read update response: %w", err)
	}

	// Handle error responses
	if resp.StatusCode != http.StatusOK {
		var regError ClientRegistrationError
		if jsonErr := json.Unmarshal(body, &regError); jsonErr == nil && regError.Error != "" {
			return nil, fmt.Errorf("update failed: %s - %s", regError.Error, regError.ErrorDescription)
		}
		return nil, fmt.Errorf("update failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse successful response
	var regResp ClientRegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return nil, fmt.Errorf("failed to parse update response: %w", err)
	}

	// Update cache
	r.mu.Lock()
	r.registrationResponse = &regResp
	r.mu.Unlock()

	// Persist updated credentials if enabled
	if r.config.PersistCredentials {
		if err := r.saveCredentials(&regResp); err != nil {
			r.logger.Errorf("Failed to persist updated credentials: %v", err)
		}
	}

	r.logger.Infof("Successfully updated client registration for client ID: %s", regResp.ClientID)
	return &regResp, nil
}

// ReadClientRegistration reads the current client registration using RFC 7592
func (r *DynamicClientRegistrar) ReadClientRegistration(ctx context.Context) (*ClientRegistrationResponse, error) {
	r.mu.RLock()
	cachedResp := r.registrationResponse
	r.mu.RUnlock()

	if cachedResp == nil {
		return nil, fmt.Errorf("no existing registration to read")
	}

	if cachedResp.RegistrationClientURI == "" || cachedResp.RegistrationAccessToken == "" {
		return nil, fmt.Errorf("registration management not supported: missing registration_client_uri or registration_access_token")
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cachedResp.RegistrationClientURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create read request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cachedResp.RegistrationAccessToken)

	// Execute request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Handle error responses
	if resp.StatusCode != http.StatusOK {
		var regError ClientRegistrationError
		if jsonErr := json.Unmarshal(body, &regError); jsonErr == nil && regError.Error != "" {
			return nil, fmt.Errorf("read failed: %s - %s", regError.Error, regError.ErrorDescription)
		}
		return nil, fmt.Errorf("read failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse successful response
	var regResp ClientRegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return nil, fmt.Errorf("failed to parse read response: %w", err)
	}

	return &regResp, nil
}

// DeleteClientRegistration deletes the client registration using RFC 7592
func (r *DynamicClientRegistrar) DeleteClientRegistration(ctx context.Context) error {
	r.mu.RLock()
	cachedResp := r.registrationResponse
	r.mu.RUnlock()

	if cachedResp == nil {
		return fmt.Errorf("no existing registration to delete")
	}

	if cachedResp.RegistrationClientURI == "" || cachedResp.RegistrationAccessToken == "" {
		return fmt.Errorf("registration management not supported: missing registration_client_uri or registration_access_token")
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, cachedResp.RegistrationClientURI, nil)
	if err != nil {
		return fmt.Errorf("failed to create delete request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cachedResp.RegistrationAccessToken)

	// Execute request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle error responses (204 No Content is success)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var regError ClientRegistrationError
		if jsonErr := json.Unmarshal(body, &regError); jsonErr == nil && regError.Error != "" {
			return fmt.Errorf("delete failed: %s - %s", regError.Error, regError.ErrorDescription)
		}
		return fmt.Errorf("delete failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Clear cache
	r.mu.Lock()
	r.registrationResponse = nil
	r.mu.Unlock()

	// Remove credentials file if persistence is enabled
	if r.config.PersistCredentials {
		filePath := r.credentialsFilePath()
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			r.logger.Errorf("Failed to remove credentials file: %v", err)
		}
	}

	r.logger.Info("Successfully deleted client registration")
	return nil
}
