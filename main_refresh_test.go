package traefikoidc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestGetNewTokenWithRefreshToken tests the GetNewTokenWithRefreshToken function
func TestGetNewTokenWithRefreshToken(t *testing.T) {
	tests := []struct {
		setupMock     func(*httptest.Server) *TraefikOidc
		validateFunc  func(*testing.T, *TokenResponse, error)
		name          string
		refreshToken  string
		expectedError string
		wantErr       bool
	}{
		{
			name:         "successful token refresh",
			refreshToken: "valid_refresh_token",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger: NewLogger("debug"),
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
				if resp.AccessToken != "refreshed_access_token" {
					t.Errorf("expected refreshed_access_token, got %s", resp.AccessToken)
				}
				if resp.IDToken != "refreshed_id_token" {
					t.Errorf("expected refreshed_id_token, got %s", resp.IDToken)
				}
				if resp.RefreshToken != "new_refresh_token" {
					t.Errorf("expected new_refresh_token, got %s", resp.RefreshToken)
				}
				if resp.TokenType != "Bearer" {
					t.Errorf("expected token type Bearer, got %s", resp.TokenType)
				}
				if resp.ExpiresIn != 3600 {
					t.Errorf("expected expires_in 3600, got %d", resp.ExpiresIn)
				}
			},
			wantErr: false,
		},
		{
			name:         "expired refresh token",
			refreshToken: "expired_refresh_token",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/expired",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger: NewLogger("debug"),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err == nil {
					t.Error("expected error for expired refresh token, got nil")
					return
				}
				if !strings.Contains(err.Error(), "invalid_grant") && !strings.Contains(err.Error(), "expired") {
					t.Errorf("expected invalid_grant or expired error, got: %v", err)
				}
			},
			wantErr:       true,
			expectedError: "invalid_grant",
		},
		{
			name:         "invalid refresh token",
			refreshToken: "invalid_refresh_token",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/invalid",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger: NewLogger("debug"),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err == nil {
					t.Error("expected error for invalid refresh token, got nil")
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
			name:         "revoked refresh token",
			refreshToken: "revoked_refresh_token",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/revoked",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger: NewLogger("debug"),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err == nil {
					t.Error("expected error for revoked refresh token, got nil")
					return
				}
				if !strings.Contains(err.Error(), "invalid_grant") && !strings.Contains(err.Error(), "revoked") {
					t.Errorf("expected invalid_grant or revoked error, got: %v", err)
				}
			},
			wantErr:       true,
			expectedError: "invalid_grant",
		},
		{
			name:         "network timeout during refresh",
			refreshToken: "valid_refresh_token",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/timeout",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 100 * time.Millisecond,
					},
					logger: NewLogger("debug"),
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
			name:         "server error during refresh",
			refreshToken: "valid_refresh_token",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/error",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger: NewLogger("debug"),
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
			refreshToken: "valid_refresh_token",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/malformed",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger: NewLogger("debug"),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err == nil {
					t.Error("expected JSON parse error, got nil")
					return
				}
				// Accept various JSON parsing error messages
				if !strings.Contains(err.Error(), "json") && !strings.Contains(err.Error(), "unmarshal") && !strings.Contains(err.Error(), "invalid character") {
					t.Errorf("expected JSON error, got: %v", err)
				}
			},
			wantErr:       true,
			expectedError: "json",
		},
		{
			name:         "partial token response (missing ID token)",
			refreshToken: "valid_refresh_token",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/partial",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger: NewLogger("debug"),
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
				if resp.AccessToken != "partial_access_token" {
					t.Errorf("expected partial_access_token, got %s", resp.AccessToken)
				}
				if resp.IDToken != "" {
					t.Errorf("expected empty ID token, got %s", resp.IDToken)
				}
			},
			wantErr: false,
		},
		{
			name:         "rate limited refresh request",
			refreshToken: "valid_refresh_token",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/ratelimit",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger: NewLogger("debug"),
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
		{
			name:         "empty refresh token",
			refreshToken: "",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger: NewLogger("debug"),
				}
			},
			validateFunc: func(t *testing.T, resp *TokenResponse, err error) {
				if err == nil {
					t.Error("expected error for empty refresh token, got nil")
					return
				}
				// The actual error should contain invalid_request
				if !strings.Contains(err.Error(), "invalid_request") && !strings.Contains(err.Error(), "missing") {
					t.Errorf("expected invalid_request or missing error, got: %v", err)
				}
				if resp != nil {
					t.Error("expected nil response for empty refresh token")
				}
			},
			wantErr:       true,
			expectedError: "invalid_request",
		},
		{
			name:         "refresh with rotating tokens",
			refreshToken: "rotating_refresh_token",
			setupMock: func(server *httptest.Server) *TraefikOidc {
				return &TraefikOidc{
					tokenURL:     server.URL + "/token/rotating",
					clientID:     "test_client",
					audience:     "test_client",
					clientSecret: "test_secret",
					tokenHTTPClient: &http.Client{
						Timeout: 10 * time.Second,
					},
					logger: NewLogger("debug"),
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
				// Verify we got a different refresh token (rotation)
				if resp.RefreshToken == "rotating_refresh_token" {
					t.Error("expected new refresh token (rotation), got same token")
				}
				if resp.RefreshToken == "" {
					t.Error("expected new refresh token, got empty")
				}
			},
			wantErr: false,
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

				// Verify grant type for refresh
				if values.Get("grant_type") != "refresh_token" {
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "unsupported_grant_type",
					})
					return
				}

				// Handle different test scenarios based on path
				switch r.URL.Path {
				case "/token":
					// Check for empty refresh token
					if values.Get("refresh_token") == "" {
						w.WriteHeader(http.StatusBadRequest)
						json.NewEncoder(w).Encode(map[string]string{
							"error":             "invalid_request",
							"error_description": "The refresh token is missing",
						})
						return
					}
					// Successful refresh
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(TokenResponse{
						AccessToken:  "refreshed_access_token",
						IDToken:      "refreshed_id_token",
						RefreshToken: "new_refresh_token",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
					})

				case "/token/expired":
					// Expired refresh token
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{
						"error":             "invalid_grant",
						"error_description": "The refresh token has expired",
					})

				case "/token/invalid":
					// Invalid refresh token
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{
						"error":             "invalid_grant",
						"error_description": "The refresh token is invalid",
					})

				case "/token/revoked":
					// Revoked refresh token
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{
						"error":             "invalid_grant",
						"error_description": "The refresh token has been revoked",
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

				case "/token/partial":
					// Partial response (missing ID token)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]interface{}{
						"access_token":  "partial_access_token",
						"refresh_token": "partial_refresh_token",
						"token_type":    "Bearer",
						"expires_in":    3600,
						// ID token intentionally missing
					})

				case "/token/ratelimit":
					// Rate limiting
					w.WriteHeader(http.StatusTooManyRequests)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "rate_limit_exceeded",
					})

				case "/token/rotating":
					// Token rotation - return different refresh token
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(TokenResponse{
						AccessToken:  "rotated_access_token",
						IDToken:      "rotated_id_token",
						RefreshToken: fmt.Sprintf("rotated_refresh_token_%d", time.Now().UnixNano()),
						TokenType:    "Bearer",
						ExpiresIn:    3600,
					})

				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Setup TraefikOidc instance
			oidc := tt.setupMock(server)

			// Execute the function
			resp, err := oidc.GetNewTokenWithRefreshToken(tt.refreshToken)

			// Validate results
			if tt.wantErr && err == nil {
				t.Errorf("expected error containing %q, got nil", tt.expectedError)
			} else if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			} else if tt.wantErr && err != nil && tt.expectedError != "" {
				// Check if error message contains expected string
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Logf("Error doesn't contain expected string %q: %v", tt.expectedError, err)
				}
			}

			// Run custom validation
			if tt.validateFunc != nil {
				tt.validateFunc(t, resp, err)
			}
		})
	}
}

// TestGetNewTokenWithRefreshToken_Concurrency tests concurrent refresh scenarios
func TestGetNewTokenWithRefreshToken_Concurrency(t *testing.T) {
	t.Run("multiple concurrent refreshes with same token", func(t *testing.T) {
		refreshCount := 0
		var mu sync.Mutex

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			refreshCount++
			count := refreshCount
			mu.Unlock()

			// Simulate processing time
			time.Sleep(50 * time.Millisecond)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(TokenResponse{
				AccessToken:  fmt.Sprintf("access_token_%d", count),
				IDToken:      fmt.Sprintf("id_token_%d", count),
				RefreshToken: fmt.Sprintf("refresh_token_%d", count),
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
			logger: NewLogger("debug"),
		}

		// Run multiple concurrent refreshes with the same token
		const numRequests = 5
		results := make(chan *TokenResponse, numRequests)
		errors := make(chan error, numRequests)

		var wg sync.WaitGroup
		wg.Add(numRequests)

		for i := 0; i < numRequests; i++ {
			go func() {
				defer wg.Done()
				resp, err := oidc.GetNewTokenWithRefreshToken("same_refresh_token")
				if err != nil {
					errors <- err
				} else {
					results <- resp
				}
			}()
		}

		wg.Wait()
		close(results)
		close(errors)

		// Verify all requests completed
		successCount := len(results)
		errorCount := len(errors)

		if successCount != numRequests {
			t.Errorf("expected %d successful refreshes, got %d", numRequests, successCount)
		}
		if errorCount > 0 {
			t.Errorf("got %d errors in concurrent refreshes", errorCount)
		}

		// Verify we actually made concurrent requests
		mu.Lock()
		finalCount := refreshCount
		mu.Unlock()

		if finalCount != numRequests {
			t.Errorf("expected %d refresh calls, got %d", numRequests, finalCount)
		}
	})

	t.Run("race condition detection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return successful response
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(TokenResponse{
				AccessToken:  "race_test_access_token",
				IDToken:      "race_test_id_token",
				RefreshToken: "race_test_refresh_token",
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
			logger: NewLogger("debug"),
		}

		// Run with race detector (go test -race will catch issues)
		const numGoroutines = 10
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				token := fmt.Sprintf("refresh_token_%d", id)
				_, _ = oidc.GetNewTokenWithRefreshToken(token)
			}(i)
		}

		wg.Wait()
	})
}

// TestGetNewTokenWithRefreshToken_ErrorRecovery tests error recovery scenarios
func TestGetNewTokenWithRefreshToken_ErrorRecovery(t *testing.T) {
	t.Run("recovery after temporary failure", func(t *testing.T) {
		attemptCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++

			// Fail first two attempts, succeed on third
			if attemptCount <= 2 {
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "temporarily_unavailable",
				})
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(TokenResponse{
				AccessToken:  "recovered_access_token",
				IDToken:      "recovered_id_token",
				RefreshToken: "recovered_refresh_token",
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
			logger: NewLogger("debug"),
		}

		// First two attempts should fail
		for i := 0; i < 2; i++ {
			resp, err := oidc.GetNewTokenWithRefreshToken("test_refresh_token")
			if err == nil {
				t.Errorf("expected error on attempt %d, got success", i+1)
			}
			if resp != nil {
				t.Errorf("expected nil response on attempt %d", i+1)
			}
		}

		// Third attempt should succeed
		resp, err := oidc.GetNewTokenWithRefreshToken("test_refresh_token")
		if err != nil {
			t.Errorf("unexpected error on recovery attempt: %v", err)
		}
		if resp == nil || resp.AccessToken != "recovered_access_token" {
			t.Error("expected successful recovery")
		}
	})
}
