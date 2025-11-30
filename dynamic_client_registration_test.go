package traefikoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDynamicClientRegistrarCreation tests creating a new DCR registrar
func TestDynamicClientRegistrarCreation(t *testing.T) {
	tests := []struct {
		name        string
		httpClient  *http.Client
		logger      *Logger
		dcrConfig   *DynamicClientRegistrationConfig
		providerURL string
	}{
		{
			name:       "with all parameters",
			httpClient: &http.Client{},
			logger:     NewLogger("DEBUG"),
			dcrConfig: &DynamicClientRegistrationConfig{
				Enabled: true,
				ClientMetadata: &ClientRegistrationMetadata{
					RedirectURIs: []string{"https://example.com/callback"},
					ClientName:   "Test Client",
				},
			},
			providerURL: "https://example.com",
		},
		{
			name:       "with nil logger",
			httpClient: &http.Client{},
			logger:     nil,
			dcrConfig: &DynamicClientRegistrationConfig{
				Enabled: true,
			},
			providerURL: "https://example.com",
		},
		{
			name:        "with nil config",
			httpClient:  &http.Client{},
			logger:      NewLogger("DEBUG"),
			dcrConfig:   nil,
			providerURL: "https://example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registrar := NewDynamicClientRegistrar(tc.httpClient, tc.logger, tc.dcrConfig, tc.providerURL)

			if registrar == nil {
				t.Fatal("Expected non-nil registrar")
			}

			if registrar.httpClient != tc.httpClient {
				t.Error("HTTP client not set correctly")
			}

			if registrar.providerURL != tc.providerURL {
				t.Errorf("Provider URL mismatch: got %s, want %s", registrar.providerURL, tc.providerURL)
			}

			if registrar.config != tc.dcrConfig {
				t.Error("Config not set correctly")
			}

			// Logger should never be nil (fallback to no-op logger)
			if registrar.logger == nil {
				t.Error("Logger should not be nil")
			}
		})
	}
}

// TestRegisterClientSuccess tests successful client registration
func TestRegisterClientSuccess(t *testing.T) {
	// Create mock server that returns successful registration response
	expectedClientID := "test-client-id-12345"
	expectedClientSecret := "test-client-secret-67890"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type: application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Parse request body
		var reqBody map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Verify redirect_uris is present
		if _, ok := reqBody["redirect_uris"]; !ok {
			t.Error("redirect_uris missing from request")
		}

		// Return successful response
		resp := ClientRegistrationResponse{
			ClientID:              expectedClientID,
			ClientSecret:          expectedClientSecret,
			ClientIDIssuedAt:      time.Now().Unix(),
			ClientSecretExpiresAt: 0, // Never expires
			RedirectURIs:          []string{"https://example.com/callback"},
			ResponseTypes:         []string{"code"},
			GrantTypes:            []string{"authorization_code", "refresh_token"},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create registrar
	dcrConfig := &DynamicClientRegistrationConfig{
		Enabled: true,
		ClientMetadata: &ClientRegistrationMetadata{
			RedirectURIs: []string{"https://example.com/callback"},
			ClientName:   "Test Client",
		},
	}

	registrar := NewDynamicClientRegistrar(
		server.Client(),
		NewLogger("DEBUG"),
		dcrConfig,
		server.URL,
	)

	// Perform registration
	ctx := context.Background()
	resp, err := registrar.RegisterClient(ctx, server.URL+"/register")

	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	if resp.ClientID != expectedClientID {
		t.Errorf("ClientID mismatch: got %s, want %s", resp.ClientID, expectedClientID)
	}

	if resp.ClientSecret != expectedClientSecret {
		t.Errorf("ClientSecret mismatch: got %s, want %s", resp.ClientSecret, expectedClientSecret)
	}

	// Verify response is cached
	cached := registrar.GetCachedResponse()
	if cached == nil {
		t.Fatal("Response should be cached")
	}
	if cached.ClientID != expectedClientID {
		t.Errorf("Cached ClientID mismatch: got %s, want %s", cached.ClientID, expectedClientID)
	}
}

// TestRegisterClientWithInitialAccessToken tests registration with an initial access token
func TestRegisterClientWithInitialAccessToken(t *testing.T) {
	expectedToken := "initial-access-token-12345"
	receivedToken := ""

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture the authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			receivedToken = authHeader
		}

		resp := ClientRegistrationResponse{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	dcrConfig := &DynamicClientRegistrationConfig{
		Enabled:            true,
		InitialAccessToken: expectedToken,
		ClientMetadata: &ClientRegistrationMetadata{
			RedirectURIs: []string{"https://example.com/callback"},
		},
	}

	registrar := NewDynamicClientRegistrar(
		server.Client(),
		NewLogger("DEBUG"),
		dcrConfig,
		server.URL,
	)

	ctx := context.Background()
	_, err := registrar.RegisterClient(ctx, server.URL+"/register")

	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	expectedAuthHeader := "Bearer " + expectedToken
	if receivedToken != expectedAuthHeader {
		t.Errorf("Authorization header mismatch: got %s, want %s", receivedToken, expectedAuthHeader)
	}
}

// TestRegisterClientError tests error handling during registration
func TestRegisterClientError(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		expectError    bool
		errorContains  string
	}{
		{
			name: "invalid_redirect_uri error",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := ClientRegistrationError{
					Error:            "invalid_redirect_uri",
					ErrorDescription: "The redirect_uri is not valid",
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   true,
			errorContains: "invalid_redirect_uri",
		},
		{
			name: "invalid_client_metadata error",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := ClientRegistrationError{
					Error:            "invalid_client_metadata",
					ErrorDescription: "Missing required field",
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   true,
			errorContains: "invalid_client_metadata",
		},
		{
			name: "server error",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Internal Server Error"))
			},
			expectError:   true,
			errorContains: "500",
		},
		{
			name: "missing client_id in response",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				resp := map[string]string{
					"client_secret": "some-secret",
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(resp)
			},
			expectError:   true,
			errorContains: "missing client_id",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(tc.serverResponse))
			defer server.Close()

			dcrConfig := &DynamicClientRegistrationConfig{
				Enabled: true,
				ClientMetadata: &ClientRegistrationMetadata{
					RedirectURIs: []string{"https://example.com/callback"},
				},
			}

			registrar := NewDynamicClientRegistrar(
				server.Client(),
				NewLogger("DEBUG"),
				dcrConfig,
				server.URL,
			)

			ctx := context.Background()
			_, err := registrar.RegisterClient(ctx, server.URL+"/register")

			if tc.expectError {
				if err == nil {
					t.Fatal("Expected error but got nil")
				}
				if tc.errorContains != "" && !stringContains(err.Error(), tc.errorContains) {
					t.Errorf("Error should contain %q, got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestRegisterClientDisabled tests that registration fails when not enabled
func TestRegisterClientDisabled(t *testing.T) {
	tests := []struct {
		name      string
		dcrConfig *DynamicClientRegistrationConfig
	}{
		{
			name:      "nil config",
			dcrConfig: nil,
		},
		{
			name: "enabled=false",
			dcrConfig: &DynamicClientRegistrationConfig{
				Enabled: false,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registrar := NewDynamicClientRegistrar(
				&http.Client{},
				NewLogger("DEBUG"),
				tc.dcrConfig,
				"https://example.com",
			)

			ctx := context.Background()
			_, err := registrar.RegisterClient(ctx, "https://example.com/register")

			if err == nil {
				t.Fatal("Expected error when DCR is disabled")
			}

			if !stringContains(err.Error(), "not enabled") {
				t.Errorf("Error should mention 'not enabled', got: %v", err)
			}
		})
	}
}

// TestRegisterClientMissingRedirectURIs tests that registration fails without redirect_uris
func TestRegisterClientMissingRedirectURIs(t *testing.T) {
	dcrConfig := &DynamicClientRegistrationConfig{
		Enabled: true,
		ClientMetadata: &ClientRegistrationMetadata{
			ClientName: "Test Client",
			// Missing RedirectURIs
		},
	}

	registrar := NewDynamicClientRegistrar(
		&http.Client{},
		NewLogger("DEBUG"),
		dcrConfig,
		"https://example.com",
	)

	ctx := context.Background()
	_, err := registrar.RegisterClient(ctx, "https://example.com/register")

	if err == nil {
		t.Fatal("Expected error when redirect_uris is missing")
	}

	if !stringContains(err.Error(), "redirect_uris") {
		t.Errorf("Error should mention 'redirect_uris', got: %v", err)
	}
}

// TestRegisterClientNoEndpoint tests that registration fails without an endpoint
func TestRegisterClientNoEndpoint(t *testing.T) {
	dcrConfig := &DynamicClientRegistrationConfig{
		Enabled: true,
		ClientMetadata: &ClientRegistrationMetadata{
			RedirectURIs: []string{"https://example.com/callback"},
		},
	}

	registrar := NewDynamicClientRegistrar(
		&http.Client{},
		NewLogger("DEBUG"),
		dcrConfig,
		"https://example.com",
	)

	ctx := context.Background()
	_, err := registrar.RegisterClient(ctx, "") // Empty endpoint

	if err == nil {
		t.Fatal("Expected error when registration endpoint is missing")
	}

	if !stringContains(err.Error(), "no registration endpoint") {
		t.Errorf("Error should mention 'no registration endpoint', got: %v", err)
	}
}

// TestRegisterClientHTTPSRequired tests that HTTPS is required for non-localhost endpoints
func TestRegisterClientHTTPSRequired(t *testing.T) {
	dcrConfig := &DynamicClientRegistrationConfig{
		Enabled: true,
		ClientMetadata: &ClientRegistrationMetadata{
			RedirectURIs: []string{"https://example.com/callback"},
		},
	}

	registrar := NewDynamicClientRegistrar(
		&http.Client{},
		NewLogger("DEBUG"),
		dcrConfig,
		"https://example.com",
	)

	ctx := context.Background()
	_, err := registrar.RegisterClient(ctx, "http://example.com/register") // HTTP instead of HTTPS

	if err == nil {
		t.Fatal("Expected error when using HTTP for non-localhost endpoint")
	}

	if !stringContains(err.Error(), "HTTPS") {
		t.Errorf("Error should mention 'HTTPS', got: %v", err)
	}
}

// TestRegisterClientCredentialsPersistence tests saving and loading credentials
func TestRegisterClientCredentialsPersistence(t *testing.T) {
	// Create a temp file for credentials
	tempDir := t.TempDir()
	credentialsFile := filepath.Join(tempDir, "test-credentials.json")

	expectedClientID := "persisted-client-id"
	expectedClientSecret := "persisted-client-secret"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ClientRegistrationResponse{
			ClientID:     expectedClientID,
			ClientSecret: expectedClientSecret,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	dcrConfig := &DynamicClientRegistrationConfig{
		Enabled:            true,
		PersistCredentials: true,
		CredentialsFile:    credentialsFile,
		ClientMetadata: &ClientRegistrationMetadata{
			RedirectURIs: []string{"https://example.com/callback"},
		},
	}

	registrar := NewDynamicClientRegistrar(
		server.Client(),
		NewLogger("DEBUG"),
		dcrConfig,
		server.URL,
	)

	// First registration - should hit the server
	ctx := context.Background()
	resp, err := registrar.RegisterClient(ctx, server.URL+"/register")
	if err != nil {
		t.Fatalf("First registration failed: %v", err)
	}

	if resp.ClientID != expectedClientID {
		t.Errorf("ClientID mismatch: got %s, want %s", resp.ClientID, expectedClientID)
	}

	// Verify credentials file was created
	if _, err := os.Stat(credentialsFile); os.IsNotExist(err) {
		t.Fatal("Credentials file was not created")
	}

	// Create a new registrar to test loading
	registrar2 := NewDynamicClientRegistrar(
		server.Client(),
		NewLogger("DEBUG"),
		dcrConfig,
		server.URL,
	)

	// Second registration - should load from file
	resp2, err := registrar2.RegisterClient(ctx, server.URL+"/register")
	if err != nil {
		t.Fatalf("Second registration failed: %v", err)
	}

	if resp2.ClientID != expectedClientID {
		t.Errorf("Loaded ClientID mismatch: got %s, want %s", resp2.ClientID, expectedClientID)
	}
}

// TestCredentialsValidation tests the areCredentialsValid function
func TestCredentialsValidation(t *testing.T) {
	dcrConfig := &DynamicClientRegistrationConfig{Enabled: true}
	registrar := NewDynamicClientRegistrar(&http.Client{}, NewLogger("DEBUG"), dcrConfig, "https://example.com")

	tests := []struct {
		name     string
		response *ClientRegistrationResponse
		expected bool
	}{
		{
			name:     "nil response",
			response: nil,
			expected: false,
		},
		{
			name: "empty client_id",
			response: &ClientRegistrationResponse{
				ClientID: "",
			},
			expected: false,
		},
		{
			name: "valid non-expiring credentials",
			response: &ClientRegistrationResponse{
				ClientID:              "test-client-id",
				ClientSecretExpiresAt: 0, // Never expires
			},
			expected: true,
		},
		{
			name: "valid future-expiring credentials",
			response: &ClientRegistrationResponse{
				ClientID:              "test-client-id",
				ClientSecretExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			},
			expected: true,
		},
		{
			name: "expired credentials",
			response: &ClientRegistrationResponse{
				ClientID:              "test-client-id",
				ClientSecretExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
			},
			expected: false,
		},
		{
			name: "about to expire credentials (within 5 min buffer)",
			response: &ClientRegistrationResponse{
				ClientID:              "test-client-id",
				ClientSecretExpiresAt: time.Now().Add(2 * time.Minute).Unix(),
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := registrar.areCredentialsValid(tc.response)
			if result != tc.expected {
				t.Errorf("areCredentialsValid() = %v, want %v", result, tc.expected)
			}
		})
	}
}

// TestBuildRegistrationRequest tests the request body construction
func TestBuildRegistrationRequest(t *testing.T) {
	tests := []struct {
		name           string
		metadata       *ClientRegistrationMetadata
		expectedFields map[string]interface{}
		expectError    bool
	}{
		{
			name: "minimal metadata",
			metadata: &ClientRegistrationMetadata{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			expectedFields: map[string]interface{}{
				"redirect_uris":              []interface{}{"https://example.com/callback"},
				"response_types":             []interface{}{"code"},
				"grant_types":                []interface{}{"authorization_code", "refresh_token"},
				"token_endpoint_auth_method": "client_secret_basic",
			},
			expectError: false,
		},
		{
			name: "full metadata",
			metadata: &ClientRegistrationMetadata{
				RedirectURIs:            []string{"https://example.com/callback", "https://example.com/callback2"},
				ResponseTypes:           []string{"code", "token"},
				GrantTypes:              []string{"authorization_code"},
				ApplicationType:         "web",
				Contacts:                []string{"admin@example.com"},
				ClientName:              "My Test Client",
				LogoURI:                 "https://example.com/logo.png",
				ClientURI:               "https://example.com",
				PolicyURI:               "https://example.com/privacy",
				TOSURI:                  "https://example.com/tos",
				SubjectType:             "public",
				TokenEndpointAuthMethod: "client_secret_post",
				DefaultMaxAge:           3600,
				RequireAuthTime:         true,
				Scope:                   "openid profile email",
			},
			expectedFields: map[string]interface{}{
				"redirect_uris":              []interface{}{"https://example.com/callback", "https://example.com/callback2"},
				"response_types":             []interface{}{"code", "token"},
				"grant_types":                []interface{}{"authorization_code"},
				"application_type":           "web",
				"client_name":                "My Test Client",
				"token_endpoint_auth_method": "client_secret_post",
				"default_max_age":            float64(3600),
				"require_auth_time":          true,
				"scope":                      "openid profile email",
			},
			expectError: false,
		},
		{
			name: "missing redirect_uris",
			metadata: &ClientRegistrationMetadata{
				ClientName: "Test Client",
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dcrConfig := &DynamicClientRegistrationConfig{
				Enabled:        true,
				ClientMetadata: tc.metadata,
			}

			registrar := NewDynamicClientRegistrar(
				&http.Client{},
				NewLogger("DEBUG"),
				dcrConfig,
				"https://example.com",
			)

			reqBody, err := registrar.buildRegistrationRequest()

			if tc.expectError {
				if err == nil {
					t.Fatal("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			var reqData map[string]interface{}
			if err := json.Unmarshal(reqBody, &reqData); err != nil {
				t.Fatalf("Failed to unmarshal request body: %v", err)
			}

			for field, expectedValue := range tc.expectedFields {
				actualValue, ok := reqData[field]
				if !ok {
					t.Errorf("Missing expected field: %s", field)
					continue
				}

				// Compare JSON representations for slices
				expectedJSON, _ := json.Marshal(expectedValue)
				actualJSON, _ := json.Marshal(actualValue)
				if string(expectedJSON) != string(actualJSON) {
					t.Errorf("Field %s mismatch: got %v, want %v", field, actualValue, expectedValue)
				}
			}
		})
	}
}

// TestProviderMetadataRegistrationEndpoint tests that registration_endpoint is parsed from metadata
func TestProviderMetadataRegistrationEndpoint(t *testing.T) {
	metadata := &ProviderMetadata{
		Issuer:          "https://example.com",
		AuthURL:         "https://example.com/authorize",
		TokenURL:        "https://example.com/token",
		JWKSURL:         "https://example.com/.well-known/jwks.json",
		RegistrationURL: "https://example.com/register",
	}

	if metadata.RegistrationURL != "https://example.com/register" {
		t.Errorf("RegistrationURL not set correctly: got %s", metadata.RegistrationURL)
	}
}

// TestDCRConfigDefaults tests default configuration values
func TestDCRConfigDefaults(t *testing.T) {
	dcrConfig := &DynamicClientRegistrationConfig{
		Enabled: true,
	}

	registrar := NewDynamicClientRegistrar(
		&http.Client{},
		NewLogger("DEBUG"),
		dcrConfig,
		"https://example.com",
	)

	// Test default credentials file path
	path := registrar.credentialsFilePath()
	if path != "/tmp/oidc-client-credentials.json" {
		t.Errorf("Default credentials file path mismatch: got %s", path)
	}

	// Test custom credentials file path
	dcrConfig.CredentialsFile = "/custom/path/credentials.json"
	path = registrar.credentialsFilePath()
	if path != "/custom/path/credentials.json" {
		t.Errorf("Custom credentials file path mismatch: got %s", path)
	}
}

// TestUpdateClientRegistration tests the RFC 7592 client update functionality
func TestUpdateClientRegistration(t *testing.T) {
	updateCalled := false

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			updateCalled = true

			// Verify authorization header
			if r.Header.Get("Authorization") == "" {
				t.Error("Missing Authorization header for update")
			}

			resp := ClientRegistrationResponse{
				ClientID:                "updated-client-id",
				ClientSecret:            "updated-client-secret",
				RegistrationAccessToken: "new-access-token",
				RegistrationClientURI:   r.URL.String(),
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	dcrConfig := &DynamicClientRegistrationConfig{
		Enabled: true,
		ClientMetadata: &ClientRegistrationMetadata{
			RedirectURIs: []string{"https://example.com/callback"},
		},
	}

	registrar := NewDynamicClientRegistrar(
		server.Client(),
		NewLogger("DEBUG"),
		dcrConfig,
		server.URL,
	)

	// Set up cached response with management credentials
	registrar.mu.Lock()
	registrar.registrationResponse = &ClientRegistrationResponse{
		ClientID:                "original-client-id",
		ClientSecret:            "original-client-secret",
		RegistrationAccessToken: "access-token",
		RegistrationClientURI:   server.URL + "/register/client123",
	}
	registrar.mu.Unlock()

	// Perform update
	ctx := context.Background()
	resp, err := registrar.UpdateClientRegistration(ctx)

	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if !updateCalled {
		t.Error("Update endpoint was not called")
	}

	if resp.ClientID != "updated-client-id" {
		t.Errorf("Updated ClientID mismatch: got %s", resp.ClientID)
	}
}

// TestDeleteClientRegistration tests the RFC 7592 client deletion functionality
func TestDeleteClientRegistration(t *testing.T) {
	deleteCalled := false

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleteCalled = true
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	tempDir := t.TempDir()
	credentialsFile := filepath.Join(tempDir, "credentials.json")

	// Create a credentials file to test deletion
	os.WriteFile(credentialsFile, []byte(`{"client_id":"test"}`), 0600)

	dcrConfig := &DynamicClientRegistrationConfig{
		Enabled:            true,
		PersistCredentials: true,
		CredentialsFile:    credentialsFile,
	}

	registrar := NewDynamicClientRegistrar(
		server.Client(),
		NewLogger("DEBUG"),
		dcrConfig,
		server.URL,
	)

	// Set up cached response with management credentials
	registrar.mu.Lock()
	registrar.registrationResponse = &ClientRegistrationResponse{
		ClientID:                "test-client-id",
		RegistrationAccessToken: "access-token",
		RegistrationClientURI:   server.URL + "/register/client123",
	}
	registrar.mu.Unlock()

	// Perform delete
	ctx := context.Background()
	err := registrar.DeleteClientRegistration(ctx)

	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if !deleteCalled {
		t.Error("Delete endpoint was not called")
	}

	// Verify cache is cleared
	if registrar.GetCachedResponse() != nil {
		t.Error("Cached response should be cleared after deletion")
	}

	// Verify credentials file is deleted
	if _, err := os.Stat(credentialsFile); !os.IsNotExist(err) {
		t.Error("Credentials file should be deleted")
	}
}

// TestReadClientRegistration tests the RFC 7592 client read functionality
func TestReadClientRegistration(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			resp := ClientRegistrationResponse{
				ClientID:        "read-client-id",
				ClientSecret:    "read-client-secret",
				RedirectURIs:    []string{"https://example.com/callback"},
				ResponseTypes:   []string{"code"},
				GrantTypes:      []string{"authorization_code"},
				ApplicationType: "web",
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	dcrConfig := &DynamicClientRegistrationConfig{Enabled: true}

	registrar := NewDynamicClientRegistrar(
		server.Client(),
		NewLogger("DEBUG"),
		dcrConfig,
		server.URL,
	)

	// Set up cached response with management credentials
	registrar.mu.Lock()
	registrar.registrationResponse = &ClientRegistrationResponse{
		ClientID:                "original-client-id",
		RegistrationAccessToken: "access-token",
		RegistrationClientURI:   server.URL + "/register/client123",
	}
	registrar.mu.Unlock()

	// Read registration
	ctx := context.Background()
	resp, err := registrar.ReadClientRegistration(ctx)

	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if resp.ClientID != "read-client-id" {
		t.Errorf("Read ClientID mismatch: got %s", resp.ClientID)
	}
}

// TestOperationsWithoutCachedResponse tests error handling when no cached response exists
func TestOperationsWithoutCachedResponse(t *testing.T) {
	dcrConfig := &DynamicClientRegistrationConfig{Enabled: true}

	registrar := NewDynamicClientRegistrar(
		&http.Client{},
		NewLogger("DEBUG"),
		dcrConfig,
		"https://example.com",
	)

	ctx := context.Background()

	// Test Update without cached response
	_, err := registrar.UpdateClientRegistration(ctx)
	if err == nil || !stringContains(err.Error(), "no existing registration") {
		t.Errorf("Update should fail without cached response: %v", err)
	}

	// Test Read without cached response
	_, err = registrar.ReadClientRegistration(ctx)
	if err == nil || !stringContains(err.Error(), "no existing registration") {
		t.Errorf("Read should fail without cached response: %v", err)
	}

	// Test Delete without cached response
	err = registrar.DeleteClientRegistration(ctx)
	if err == nil || !stringContains(err.Error(), "no existing registration") {
		t.Errorf("Delete should fail without cached response: %v", err)
	}
}

// TestOperationsWithoutManagementCredentials tests error handling without management URIs
func TestOperationsWithoutManagementCredentials(t *testing.T) {
	dcrConfig := &DynamicClientRegistrationConfig{Enabled: true}

	registrar := NewDynamicClientRegistrar(
		&http.Client{},
		NewLogger("DEBUG"),
		dcrConfig,
		"https://example.com",
	)

	// Set up cached response WITHOUT management credentials
	registrar.mu.Lock()
	registrar.registrationResponse = &ClientRegistrationResponse{
		ClientID: "test-client-id",
		// Missing RegistrationAccessToken and RegistrationClientURI
	}
	registrar.mu.Unlock()

	ctx := context.Background()

	// Test Update without management credentials
	_, err := registrar.UpdateClientRegistration(ctx)
	if err == nil || !stringContains(err.Error(), "registration management not supported") {
		t.Errorf("Update should fail without management credentials: %v", err)
	}

	// Test Read without management credentials
	_, err = registrar.ReadClientRegistration(ctx)
	if err == nil || !stringContains(err.Error(), "registration management not supported") {
		t.Errorf("Read should fail without management credentials: %v", err)
	}

	// Test Delete without management credentials
	err = registrar.DeleteClientRegistration(ctx)
	if err == nil || !stringContains(err.Error(), "registration management not supported") {
		t.Errorf("Delete should fail without management credentials: %v", err)
	}
}

// stringContains is a helper function to check if a string contains a substring
func stringContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && stringContainsHelper(s, substr))
}

func stringContainsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
