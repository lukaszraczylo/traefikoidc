package traefikoidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestExchangeCodeForToken_Comprehensive tests the ExchangeCodeForToken function comprehensively
func TestExchangeCodeForToken_Comprehensive(t *testing.T) {
	tests := []struct {
		name          string
		grantType     string
		code          string
		redirectURL   string
		codeVerifier  string
		setupMock     func(*httptest.Server) *TraefikOidc
		validateFunc  func(*testing.T, *TokenResponse, error)
		wantErr       bool
		expectedError string
	}{
		{
			name:         "successful authorization code exchange",
			grantType:    "authorization_code",
			code:         "valid_auth_code",
			redirectURL:  "https://example.com/callback",
			codeVerifier: "",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger:       NewLogger("debug"),
					initComplete: make(chan struct{}),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if resp == nil {
					t.Error("expected token response, got nil")
					return
				}
				if resp.AccessToken == "" {
					t.Error("expected access token, got empty")
				}
				if resp.IDToken == "" {
					t.Error("expected ID token, got empty")
				}
				if resp.RefreshToken == "" {
					t.Error("expected refresh token, got empty")
				}
				if resp.TokenType != "Bearer" {
					t.Errorf("expected token type Bearer, got %s", resp.TokenType)
				}
				if resp.ExpiresIn <= 0 {
					t.Error("expected positive expires_in value")
				}
			},
			wantErr: false,
		},
		{
			name:         "successful authorization code exchange with PKCE",
			grantType:    "authorization_code",
			code:         "valid_auth_code_pkce",
			redirectURL:  "https://example.com/callback",
			codeVerifier: "test_verifier_string_that_is_long_enough",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					enablePKCE:   true,
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger:       NewLogger("debug"),
					initComplete: make(chan struct{}),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if resp == nil {
					t.Error("expected token response, got nil")
					return
				}
				if resp.AccessToken == "" {
					t.Error("expected access token, got empty")
				}
			},
			wantErr: false,
		},
		{
			name:         "invalid authorization code",
			grantType:    "authorization_code",
			code:         "invalid_code",
			redirectURL:  "https://example.com/callback",
			codeVerifier: "",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/invalid",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger:       NewLogger("debug"),
					initComplete: make(chan struct{}),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err == nil {
					t.Error("expected error for invalid code, got nil")
					return
				}
				if !strings.Contains(err.Error(), "invalid_grant") {
					t.Errorf("expected invalid_grant error, got: %v", err)
				}
			},
			wantErr:       true,
			expectedError: "invalid_grant",
		},
		{
			name:         "expired authorization code",
			grantType:    "authorization_code",
			code:         "expired_code",
			redirectURL:  "https://example.com/callback",
			codeVerifier: "",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/expired",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger:       NewLogger("debug"),
					initComplete: make(chan struct{}),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err == nil {
					t.Error("expected error for expired code, got nil")
					return
				}
				if !strings.Contains(err.Error(), "expired") {
					t.Errorf("expected expired error, got: %v", err)
				}
			},
			wantErr:       true,
			expectedError: "expired",
		},
		{
			name:         "network timeout during token exchange",
			grantType:    "authorization_code",
			code:         "valid_code",
			redirectURL:  "https://example.com/callback",
			codeVerifier: "",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/timeout",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 100 * time.Millisecond,
					},
					logger:       NewLogger("debug"),
					initComplete: make(chan struct{}),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err == nil {
					t.Error("expected timeout error, got nil")
					return
				}
				if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
					t.Errorf("expected timeout error, got: %v", err)
				}
			},
			wantErr:       true,
			expectedError: "timeout",
		},
		{
			name:         "server returns 500 error",
			grantType:    "authorization_code",
			code:         "valid_code",
			redirectURL:  "https://example.com/callback",
			codeVerifier: "",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/error",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger:       NewLogger("debug"),
					initComplete: make(chan struct{}),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err == nil {
					t.Error("expected server error, got nil")
					return
				}
				if !strings.Contains(err.Error(), "500") && !strings.Contains(err.Error(), "server_error") {
					t.Errorf("expected server error, got: %v", err)
				}
			},
			wantErr:       true,
			expectedError: "server_error",
		},
		{
			name:         "malformed JSON response",
			grantType:    "authorization_code",
			code:         "valid_code",
			redirectURL:  "https://example.com/callback",
			codeVerifier: "",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/malformed",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger:       NewLogger("debug"),
					initComplete: make(chan struct{}),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err == nil {
					t.Error("expected JSON parse error, got nil")
					return
				}
				if !strings.Contains(err.Error(), "json") && !strings.Contains(err.Error(), "unmarshal") && !strings.Contains(err.Error(), "invalid character") {
					t.Errorf("expected JSON error, got: %v", err)
				}
			},
			wantErr:       true,
			expectedError: "json",
		},
		{
			name:         "missing required tokens in response",
			grantType:    "authorization_code",
			code:         "valid_code",
			redirectURL:  "https://example.com/callback",
			codeVerifier: "",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/incomplete",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger:       NewLogger("debug"),
					initComplete: make(chan struct{}),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err != nil {
					t.Logf("got error: %v", err)
				}
				if resp == nil {
					t.Error("expected partial token response, got nil")
					return
				}
				// Check that we at least got some response even if incomplete
				if resp.AccessToken == "" && resp.IDToken == "" {
					t.Error("expected at least one token in response")
				}
			},
			wantErr: false,
		},
		{
			name:         "context cancellation during exchange",
			grantType:    "authorization_code",
			code:         "valid_code",
			redirectURL:  "https://example.com/callback",
			codeVerifier: "",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/slow",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger:       NewLogger("debug"),
					initComplete: make(chan struct{}),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err == nil {
					t.Error("expected context cancellation error, got nil")
					return
				}
				if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "canceled") && !strings.Contains(err.Error(), "deadline exceeded") {
					t.Errorf("expected context canceled error, got: %v", err)
				}
			},
			wantErr:       true,
			expectedError: "canceled",
		},
		{
			name:         "rate limiting response",
			grantType:    "authorization_code",
			code:         "valid_code",
			redirectURL:  "https://example.com/callback",
			codeVerifier: "",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/ratelimit",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger:       NewLogger("debug"),
					initComplete: make(chan struct{}),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err == nil {
					t.Error("expected rate limit error, got nil")
					return
				}
				if !strings.Contains(err.Error(), "429") && !strings.Contains(err.Error(), "rate") {
					t.Errorf("expected rate limit error, got: %v", err)
				}
			},
			wantErr:       true,
			expectedError: "rate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server with various endpoints
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method
				if r.Method != http.MethodPost {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}

				// Parse request body
				body, _ := io.ReadAll(r.Body)
				values, _ := url.ParseQuery(string(body))

				// Verify required parameters
				if values.Get("grant_type") == "" || values.Get("client_id") == "" {
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "invalid_request",
					})
					return
				}

				// Handle different test scenarios based on path
				switch r.URL.Path {
				case "/token":
					// Successful response
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(TokenResponse{
						AccessToken:  "test_access_token",
						IDToken:      "test_id_token",
						RefreshToken: "test_refresh_token",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
					})

				case "/token/invalid":
					// Invalid grant
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{
						"error":             "invalid_grant",
						"error_description": "The authorization code is invalid",
					})

				case "/token/expired":
					// Expired code
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{
						"error":             "invalid_grant",
						"error_description": "The authorization code has expired",
					})

				case "/token/timeout":
					// Simulate timeout
					time.Sleep(200 * time.Millisecond)
					w.WriteHeader(http.StatusOK)

				case "/token/error":
					// Server error
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "server_error",
					})

				case "/token/malformed":
					// Malformed JSON
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`{"access_token": "test", invalid json`))

				case "/token/incomplete":
					// Incomplete response (missing some tokens)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]interface{}{
						"access_token": "partial_token",
						"token_type":   "Bearer",
						"expires_in":   3600,
					})

				case "/token/slow":
					// Slow response for context cancellation test
					time.Sleep(5 * time.Second)
					w.WriteHeader(http.StatusOK)

				case "/token/ratelimit":
					// Rate limiting
					w.WriteHeader(http.StatusTooManyRequests)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "rate_limit_exceeded",
					})

				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Setup TraefikOidc instance
			oidc := tt.setupMock(server)

			// Create context for the test
			ctx := context.Background()
			if tt.name == "context cancellation during exchange" {
				// Create a context that will be canceled quickly
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
				defer cancel()
				resp, err := oidc.ExchangeCodeForToken(ctx, tt.grantType, tt.code, tt.redirectURL, tt.codeVerifier)
				tt.validateFunc(t, resp, err)
				return
			}

			// Execute the function
			resp, err := oidc.ExchangeCodeForToken(ctx, tt.grantType, tt.code, tt.redirectURL, tt.codeVerifier)

			// Validate results
			if tt.wantErr && err == nil {
				t.Errorf("expected error containing %q, got nil", tt.expectedError)
			} else if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Run custom validation
			if tt.validateFunc != nil {
				tt.validateFunc(t, resp, err)
			}
		})
	}
}

// TestExchangeCodeForToken_Integration tests integration scenarios
func TestExchangeCodeForToken_Integration(t *testing.T) {
	t.Run("multiple concurrent exchanges", func(t *testing.T) {
		// Use atomic counter for unique token generation to handle race detector slowdown
		var tokenCounter int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add small delay to test concurrency
			time.Sleep(10 * time.Millisecond)

			// Generate unique token using atomic counter
			tokenID := atomic.AddInt64(&tokenCounter, 1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(TokenResponse{
				AccessToken:  fmt.Sprintf("token_%d", tokenID),
				IDToken:      "test_id_token",
				RefreshToken: "test_refresh_token",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			})
		}))
		defer server.Close()

		oidc := &TraefikOidc{
			tokenURL:     server.URL + "/token",
			clientID:     "test_client",
			audience:     "test_client",
			clientSecret: "test_secret",
			tokenHTTPClient: &http.Client{
				Timeout: 10 * time.Second,
			},
			logger:       NewLogger("debug"),
			initComplete: make(chan struct{}),
		}

		// Run multiple concurrent exchanges
		const numRequests = 10
		results := make(chan *TokenResponse, numRequests)
		errors := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			go func(idx int) {
				ctx := context.Background()
				resp, err := oidc.ExchangeCodeForToken(
					ctx,
					"authorization_code",
					fmt.Sprintf("code_%d", idx),
					"https://example.com/callback",
					"",
				)
				if err != nil {
					errors <- err
				} else {
					results <- resp
				}
			}(i)
		}

		// Collect results
		successCount := 0
		errorCount := 0
		tokens := make(map[string]bool)

		for i := 0; i < numRequests; i++ {
			select {
			case resp := <-results:
				successCount++
				// Verify each response has unique token
				if _, exists := tokens[resp.AccessToken]; exists {
					t.Error("duplicate access token received")
				}
				tokens[resp.AccessToken] = true
			case err := <-errors:
				errorCount++
				t.Errorf("unexpected error in concurrent request: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for concurrent requests")
			}
		}

		if successCount != numRequests {
			t.Errorf("expected %d successful exchanges, got %d", numRequests, successCount)
		}
		if errorCount > 0 {
			t.Errorf("got %d errors in concurrent exchanges", errorCount)
		}
	})

	t.Run("retry on transient failure", func(t *testing.T) {
		attemptCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++

			// Fail first attempt, succeed on second
			if attemptCount == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(TokenResponse{
				AccessToken:  "retry_success_token",
				IDToken:      "test_id_token",
				RefreshToken: "test_refresh_token",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			})
		}))
		defer server.Close()

		oidc := &TraefikOidc{
			tokenURL:     server.URL + "/token",
			clientID:     "test_client",
			audience:     "test_client",
			clientSecret: "test_secret",
			tokenHTTPClient: &http.Client{
				Timeout: 10 * time.Second,
			},
			logger:       NewLogger("debug"),
			initComplete: make(chan struct{}),
		}

		// First attempt should fail
		ctx := context.Background()
		_, err := oidc.ExchangeCodeForToken(ctx, "authorization_code", "test_code", "https://example.com/callback", "")

		if err == nil {
			t.Error("expected error on first attempt")
		}

		// Second attempt should succeed
		resp, err := oidc.ExchangeCodeForToken(ctx, "authorization_code", "test_code", "https://example.com/callback", "")

		if err != nil {
			t.Errorf("unexpected error on retry: %v", err)
		}
		if resp == nil || resp.AccessToken != "retry_success_token" {
			t.Error("expected successful response on retry")
		}
		if attemptCount != 2 {
			t.Errorf("expected 2 attempts, got %d", attemptCount)
		}
	})
}
