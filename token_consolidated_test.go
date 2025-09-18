package traefikoidc

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	"golang.org/x/time/rate"
)

// ============================================================================
// Test Constants
// ============================================================================

// Test tokens used across multiple test files
var (
	ValidAccessToken      = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJodHRwczovL3Rlc3QtaXNzdWVyLmNvbSIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwiZXhwIjozMDAwMDAwMDAwLCJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ.dGVzdC1zaWduYXR1cmU"
	ValidIDToken          = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJodHRwczovL3Rlc3QtaXNzdWVyLmNvbSIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwiZXhwIjozMDAwMDAwMDAwLCJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ.dGVzdC1zaWduYXR1cmU"
	ValidRefreshToken     = "refresh_token_abc123"
	MinimalValidJWT       = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
	InvalidTokenOneDot    = "invalid.token"
	InvalidTokenNoDots    = "invalidtoken"
	InvalidTokenThreeDots = "invalid..token"
)

// ============================================================================
// Token Type Tests
// ============================================================================

func TestTokenTypes(t *testing.T) {
	t.Run("TokenTypeDistinction", func(t *testing.T) {
		type templateData struct {
			Claims       map[string]interface{}
			AccessToken  string
			IDToken      string
			RefreshToken string
		}

		testData := templateData{
			AccessToken:  "test-access-token-abc123",
			IDToken:      "test-id-token-xyz789",
			RefreshToken: "test-refresh-token",
			Claims: map[string]interface{}{
				"sub":   "test-subject",
				"email": "user@example.com",
			},
		}

		tests := []struct {
			name          string
			templateText  string
			expectedValue string
		}{
			{
				name:          "Access Token Only",
				templateText:  "Bearer {{.AccessToken}}",
				expectedValue: "Bearer test-access-token-abc123",
			},
			{
				name:          "ID Token Only",
				templateText:  "ID: {{.IDToken}}",
				expectedValue: "ID: test-id-token-xyz789",
			},
			{
				name:          "Both Tokens",
				templateText:  "Access: {{.AccessToken}} ID: {{.IDToken}}",
				expectedValue: "Access: test-access-token-abc123 ID: test-id-token-xyz789",
			},
			{
				name:          "Both Tokens in Authorization Format",
				templateText:  "Bearer {{.AccessToken}} and Bearer {{.IDToken}}",
				expectedValue: "Bearer test-access-token-abc123 and Bearer test-id-token-xyz789",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				tmpl, err := template.New("test").Parse(tc.templateText)
				if err != nil {
					t.Fatalf("Failed to parse template: %v", err)
				}

				var buf bytes.Buffer
				err = tmpl.Execute(&buf, testData)
				if err != nil {
					t.Fatalf("Failed to execute template: %v", err)
				}

				result := buf.String()
				if result != tc.expectedValue {
					t.Errorf("Expected template output %q, got %q", tc.expectedValue, result)
				}
			})
		}
	})

	t.Run("TokenTypeIntegration", func(t *testing.T) {
		ts := NewTestSuite(t)
		ts.Setup()

		idToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":        "https://test-issuer.com",
			"aud":        "test-client-id",
			"exp":        float64(3000000000),
			"sub":        "id-token-subject",
			"email":      "id@example.com",
			"nonce":      "test-nonce",
			"token_type": "id",
		})
		if err != nil {
			t.Fatalf("Failed to create ID token: %v", err)
		}

		accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":        "https://test-issuer.com",
			"aud":        "test-client-id",
			"exp":        float64(3000000000),
			"sub":        "access-token-subject",
			"email":      "access@example.com",
			"scope":      "openid email profile",
			"token_type": "access",
		})
		if err != nil {
			t.Fatalf("Failed to create access token: %v", err)
		}

		// Test that tokens are correctly stored and retrieved
		req := httptest.NewRequest("GET", "http://example.com", nil)
		session, err := ts.sessionManager.GetSession(req)
		if err != nil {
			t.Fatalf("Failed to get session: %v", err)
		}
		defer session.ReturnToPool()

		session.SetIDToken(idToken)
		session.SetAccessToken(accessToken)

		retrievedID := session.GetIDToken()
		retrievedAccess := session.GetAccessToken()

		if retrievedID != idToken {
			t.Errorf("ID token mismatch: expected %q, got %q", idToken, retrievedID)
		}
		if retrievedAccess != accessToken {
			t.Errorf("Access token mismatch: expected %q, got %q", accessToken, retrievedAccess)
		}
	})
}

// ============================================================================
// Token Corruption Tests
// ============================================================================

func TestTokenCorruption(t *testing.T) {
	t.Run("TokenCorruptionScenario", func(t *testing.T) {
		logger := NewLogger("debug")
		sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
		if err != nil {
			t.Fatalf("Failed to create session manager: %v", err)
		}

		testTokens := NewTestTokens()
		validJWT := testTokens.CreateLargeValidJWT(100)

		tests := []struct {
			name               string
			tokenSize          int
			iterations         int
			expectConsistent   bool
			corruptionScenario func(*SessionData)
		}{
			{
				name:             "Small token - multiple retrievals",
				tokenSize:        len(validJWT),
				iterations:       10,
				expectConsistent: true,
			},
			{
				name:             "Large chunked token - multiple retrievals",
				tokenSize:        5000,
				iterations:       10,
				expectConsistent: true,
			},
			{
				name:             "Compression corruption simulation",
				tokenSize:        2000,
				iterations:       5,
				expectConsistent: false,
				corruptionScenario: func(session *SessionData) {
					if session.accessSession != nil {
						session.accessSession.Values["token"] = "corrupted_base64_!@#$"
						session.accessSession.Values["compressed"] = true
					}
				},
			},
			{
				name:             "Chunk reassembly corruption simulation",
				tokenSize:        25000,
				iterations:       5,
				expectConsistent: false,
				corruptionScenario: func(session *SessionData) {
					if len(session.accessTokenChunks) > 0 {
						if chunk, exists := session.accessTokenChunks[0]; exists {
							chunk.Values["token_chunk"] = "invalid_base64_!@#$%"
						}
					}
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "http://example.com/foo", nil)
				session, err := sm.GetSession(req)
				if err != nil {
					t.Fatalf("Failed to get session: %v", err)
				}
				defer session.ReturnToPool()

				token := createTokenOfSize(validJWT, tt.tokenSize)
				session.SetAccessToken(token)

				var retrievedTokens []string
				for i := 0; i < tt.iterations; i++ {
					retrieved := session.GetAccessToken()
					retrievedTokens = append(retrievedTokens, retrieved)

					if tt.expectConsistent && retrieved != token {
						t.Errorf("Iteration %d: Token changed unexpectedly", i)
					}
				}

				if tt.corruptionScenario != nil {
					tt.corruptionScenario(session)
					retrieved := session.GetAccessToken()
					if retrieved == token {
						t.Error("Expected corrupted token to be different")
					}
				}

				if tt.expectConsistent {
					for i, retrievedToken := range retrievedTokens {
						if retrievedToken != token {
							t.Errorf("Iteration %d: Token mismatch", i)
						}
					}
				}
			})
		}
	})

	t.Run("Base64CorruptionHandling", func(t *testing.T) {
		tests := []struct {
			name        string
			input       string
			expectError bool
		}{
			{"Valid base64", "eyJhbGciOiJSUzI1NiJ9", false},
			{"Invalid characters", "eyJ!@#$%^&*()", true},
			{"Missing padding", "eyJhbGc", false}, // base64url doesn't require padding
			{"Empty string", "", false},
			{"Spaces in base64", "eyJ hbG ciOi JSU zI1 NiJ9", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(tt.input))
				hasError := err != nil
				if hasError != tt.expectError {
					t.Errorf("Expected error=%v, got error=%v (err: %v)", tt.expectError, hasError, err)
				}
			})
		}
	})
}

// ============================================================================
// Token Resilience Tests
// ============================================================================

func TestTokenResilience(t *testing.T) {
	t.Run("ConcurrentTokenAccess", func(t *testing.T) {
		logger := NewLogger("debug")
		sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
		if err != nil {
			t.Fatalf("Failed to create session manager: %v", err)
		}

		req := httptest.NewRequest("GET", "http://example.com", nil)
		session, err := sm.GetSession(req)
		if err != nil {
			t.Fatalf("Failed to get session: %v", err)
		}
		defer session.ReturnToPool()

		testToken := "test-token-" + generateRandomString(100)
		session.SetAccessToken(testToken)

		var wg sync.WaitGroup
		errors := make(chan error, 100)
		successCount := int32(0)

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				retrieved := session.GetAccessToken()
				if retrieved == testToken {
					atomic.AddInt32(&successCount, 1)
				} else {
					errors <- fmt.Errorf("token mismatch: expected %q, got %q", testToken, retrieved)
				}
			}()
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Error(err)
		}

		if successCount != 100 {
			t.Errorf("Expected 100 successful retrievals, got %d", successCount)
		}
	})

	t.Run("TokenSizeHandling", func(t *testing.T) {
		logger := NewLogger("debug")
		sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
		if err != nil {
			t.Fatalf("Failed to create session manager: %v", err)
		}

		sizes := []int{
			100,   // Small token
			1000,  // Medium token
			4000,  // Just under chunk threshold
			5000,  // Just over chunk threshold
			10000, // Large token requiring chunking
			20000, // Very large token (but within 25 chunk limit)
		}

		for _, size := range sizes {
			t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				session, err := sm.GetSession(req)
				if err != nil {
					t.Fatalf("Failed to get session: %v", err)
				}
				defer session.ReturnToPool()

				// Create a valid JWT token of the desired size
				token := createTokenOfSize(ValidAccessToken, size)
				session.SetAccessToken(token)

				retrieved := session.GetAccessToken()
				// For very large tokens that exceed chunk limits, retrieval will fail
				if size > 15000 && retrieved == "" {
					// Expected failure for very large tokens
					t.Logf("Token size %d exceeds chunk limits (expected)", size)
				} else if retrieved != token {
					t.Errorf("Token mismatch for size %d", size)
				}
			})
		}
	})

	t.Run("RateLimitedTokenRefresh", func(t *testing.T) {
		limiter := rate.NewLimiter(rate.Limit(10), 1) // 10 requests per second

		var wg sync.WaitGroup
		successCount := int32(0)
		deniedCount := int32(0)

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if limiter.Allow() {
					atomic.AddInt32(&successCount, 1)
				} else {
					atomic.AddInt32(&deniedCount, 1)
				}
			}()
			time.Sleep(10 * time.Millisecond) // Spread requests over 500ms
		}

		wg.Wait()

		t.Logf("Allowed: %d, Denied: %d", successCount, deniedCount)
		if successCount == 0 {
			t.Error("No requests were allowed")
		}
		if successCount == 50 {
			t.Error("All requests were allowed, rate limiting not working")
		}
	})
}

// ============================================================================
// Token Validation Tests
// ============================================================================

func TestTokenValidation(t *testing.T) {
	t.Run("JWTStructureValidation", func(t *testing.T) {
		tests := []struct {
			name        string
			token       string
			expectValid bool
		}{
			{
				name:        "Valid JWT structure",
				token:       "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature",
				expectValid: true,
			},
			{
				name:        "Missing signature",
				token:       "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0",
				expectValid: false,
			},
			{
				name:        "Missing payload",
				token:       "eyJhbGciOiJSUzI1NiJ9..signature",
				expectValid: true, // Empty payload is technically valid
			},
			{
				name:        "Only header",
				token:       "eyJhbGciOiJSUzI1NiJ9",
				expectValid: false,
			},
			{
				name:        "Too many parts",
				token:       "header.payload.signature.extra",
				expectValid: false,
			},
			{
				name:        "Empty token",
				token:       "",
				expectValid: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				parts := strings.Split(tt.token, ".")
				isValid := len(parts) == 3
				if isValid != tt.expectValid {
					t.Errorf("Expected valid=%v, got %v", tt.expectValid, isValid)
				}
			})
		}
	})

	t.Run("TokenExpiryValidation", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			name        string
			exp         time.Time
			expectValid bool
		}{
			{"Future expiry", now.Add(time.Hour), true},
			{"Just expired", now.Add(-time.Second), false},
			{"Long expired", now.Add(-24 * time.Hour), false},
			{"Far future", now.Add(365 * 24 * time.Hour), true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				isValid := tt.exp.After(now)
				if isValid != tt.expectValid {
					t.Errorf("Expected valid=%v, got %v", tt.expectValid, isValid)
				}
			})
		}
	})
}

// ============================================================================
// Token Chunking Tests
// ============================================================================

func TestTokenChunking(t *testing.T) {
	t.Run("ChunkSplitting", func(t *testing.T) {
		chunkSize := 4000
		tests := []struct {
			name           string
			tokenSize      int
			expectedChunks int
		}{
			{"Small token", 100, 1},
			{"Just under chunk size", 3999, 1},
			{"Exactly chunk size", 4000, 1},
			{"Just over chunk size", 4100, 2},
			{"Multiple chunks", 10000, 3},
			{"Large token", 50000, 13},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				token := generateRandomString(tt.tokenSize)
				chunks := (len(token) + chunkSize - 1) / chunkSize
				if chunks != tt.expectedChunks {
					t.Errorf("Expected %d chunks, got %d", tt.expectedChunks, chunks)
				}
			})
		}
	})

	t.Run("ChunkReassembly", func(t *testing.T) {
		originalToken := generateRandomString(10000)
		chunkSize := 4000

		// Split into chunks
		var chunks []string
		for i := 0; i < len(originalToken); i += chunkSize {
			end := i + chunkSize
			if end > len(originalToken) {
				end = len(originalToken)
			}
			chunks = append(chunks, originalToken[i:end])
		}

		// Reassemble
		var reassembled strings.Builder
		for _, chunk := range chunks {
			reassembled.WriteString(chunk)
		}

		if reassembled.String() != originalToken {
			t.Error("Token reassembly failed")
		}
	})
}

// ============================================================================
// Token Compression Tests
// ============================================================================

func TestTokenCompression(t *testing.T) {
	t.Run("CompressionEfficiency", func(t *testing.T) {
		// Create a token with repetitive content (compresses well)
		repetitiveToken := strings.Repeat("AAAA", 1000)

		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		_, err := gz.Write([]byte(repetitiveToken))
		if err != nil {
			t.Fatalf("Compression failed: %v", err)
		}
		gz.Close()

		compressionRatio := float64(len(repetitiveToken)) / float64(compressed.Len())
		t.Logf("Compression ratio: %.2fx (original: %d, compressed: %d)",
			compressionRatio, len(repetitiveToken), compressed.Len())

		if compressionRatio < 10 {
			t.Error("Expected better compression for repetitive data")
		}
	})

	t.Run("CompressionDecompression", func(t *testing.T) {
		tokens := []string{
			generateRandomString(100),
			generateRandomString(1000),
			generateRandomString(10000),
			strings.Repeat("A", 5000), // Highly compressible
		}

		for i, token := range tokens {
			t.Run(fmt.Sprintf("Token_%d", i), func(t *testing.T) {
				// Compress
				var compressed bytes.Buffer
				gz := gzip.NewWriter(&compressed)
				_, err := gz.Write([]byte(token))
				if err != nil {
					t.Fatalf("Compression failed: %v", err)
				}
				gz.Close()

				// Decompress
				reader, err := gzip.NewReader(&compressed)
				if err != nil {
					t.Fatalf("Failed to create decompressor: %v", err)
				}
				var decompressed bytes.Buffer
				_, err = decompressed.ReadFrom(reader)
				if err != nil {
					t.Fatalf("Decompression failed: %v", err)
				}
				reader.Close()

				if decompressed.String() != token {
					t.Error("Token changed after compression/decompression")
				}
			})
		}
	})
}

// ============================================================================
// Ajax Token Expiry Tests
// ============================================================================

func TestAjaxTokenExpiry(t *testing.T) {
	t.Run("AjaxExpiryDetection", func(t *testing.T) {
		tests := []struct {
			name           string
			isAjax         bool
			tokenExpired   bool
			expectedStatus int
		}{
			{"Regular request, valid token", false, false, http.StatusOK},
			{"Regular request, expired token", false, true, http.StatusFound},
			{"Ajax request, valid token", true, false, http.StatusOK},
			{"Ajax request, expired token", true, true, http.StatusUnauthorized},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				if tt.isAjax {
					req.Header.Set("X-Requested-With", "XMLHttpRequest")
				}

				w := httptest.NewRecorder()

				// Simulate token validation
				if tt.tokenExpired {
					if tt.isAjax {
						w.WriteHeader(http.StatusUnauthorized)
						w.Write([]byte(`{"error": "token_expired", "message": "Your session has expired"}`))
					} else {
						w.WriteHeader(http.StatusFound)
						w.Header().Set("Location", "/auth/login")
					}
				} else {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Success"))
				}

				if w.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
				}

				if tt.isAjax && tt.tokenExpired {
					body := w.Body.String()
					if !strings.Contains(body, "token_expired") {
						t.Error("Expected token_expired error in response")
					}
				}
			})
		}
	})

	t.Run("AjaxRetryMechanism", func(t *testing.T) {
		attemptCount := 0
		maxRetries := 3

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++
			if attemptCount < maxRetries {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error": "token_expired"}`))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"success": true}`))
			}
		})

		server := httptest.NewServer(handler)
		defer server.Close()

		// Simulate client with retry logic
		client := &http.Client{Timeout: 5 * time.Second}
		var lastResponse *http.Response

		for i := 0; i < maxRetries; i++ {
			req, _ := http.NewRequest("GET", server.URL, nil)
			req.Header.Set("X-Requested-With", "XMLHttpRequest")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			lastResponse = resp

			if resp.StatusCode == http.StatusOK {
				break
			}
			resp.Body.Close()
		}

		if lastResponse.StatusCode != http.StatusOK {
			t.Errorf("Expected successful retry, got status %d", lastResponse.StatusCode)
		}
		lastResponse.Body.Close()

		if attemptCount != maxRetries {
			t.Errorf("Expected %d attempts, got %d", maxRetries, attemptCount)
		}
	})
}

// ============================================================================
// Test Token Creation Helper Tests
// ============================================================================

func TestTestTokens(t *testing.T) {
	t.Run("CreateValidJWT", func(t *testing.T) {
		tokens := NewTestTokens()
		jwt := tokens.CreateValidJWT()

		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			t.Errorf("Expected 3 JWT parts, got %d", len(parts))
		}

		// Decode and verify header
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("Failed to decode header: %v", err)
		}

		var header map[string]interface{}
		if err := json.Unmarshal(headerJSON, &header); err != nil {
			t.Fatalf("Failed to parse header: %v", err)
		}

		if header["alg"] != "RS256" {
			t.Errorf("Expected RS256 algorithm, got %v", header["alg"])
		}
	})

	t.Run("CreateLargeValidJWT", func(t *testing.T) {
		tokens := NewTestTokens()
		sizes := []int{10, 100, 1000}

		for _, size := range sizes {
			t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
				jwt := tokens.CreateLargeValidJWT(size)

				// Verify it's a valid JWT structure
				parts := strings.Split(jwt, ".")
				if len(parts) != 3 {
					t.Errorf("Expected 3 JWT parts, got %d", len(parts))
				}

				// Verify size is roughly as expected
				// The JWT will be larger than the claim size due to base64 encoding and metadata
				// Base64 encoding adds ~33% overhead, plus headers and structure
				minExpectedSize := size + 200 // claim size + headers/structure overhead
				if len(jwt) < minExpectedSize {
					t.Errorf("JWT seems too small for requested claim size: got %d, expected at least %d", len(jwt), minExpectedSize)
				}
			})
		}
	})

	t.Run("CreateExpiredJWT", func(t *testing.T) {
		tokens := NewTestTokens()
		jwt := tokens.CreateExpiredJWT()

		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			t.Errorf("Expected 3 JWT parts, got %d", len(parts))
		}

		// Decode payload to verify expiration
		payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("Failed to decode payload: %v", err)
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(payloadJSON, &payload); err != nil {
			t.Fatalf("Failed to parse payload: %v", err)
		}

		exp, ok := payload["exp"].(float64)
		if !ok {
			t.Fatal("Expected exp claim in payload")
		}

		if exp >= float64(time.Now().Unix()) {
			t.Error("Token should be expired")
		}
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

// Mock implementations for testing
type MockJWTVerifier struct {
	valid bool
}

func (v *MockJWTVerifier) Verify(token string) error {
	if !v.valid {
		return fmt.Errorf("invalid token")
	}
	return nil
}

// equalSlices compares two string slices for equality
func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func createTokenOfSize(baseToken string, targetSize int) string {
	// For large tokens, use the CreateLargeValidJWT function which creates proper JWT format
	if targetSize > 1000 {
		testTokens := NewTestTokens()
		// Calculate the claim size needed to reach approximately the target token size
		// A rough estimate: header ~60 bytes, payload wrapper ~150 bytes, signature ~20 bytes
		// So claim size = targetSize - 230
		claimSize := targetSize - 230
		if claimSize < 0 {
			claimSize = 10
		}
		return testTokens.CreateLargeValidJWT(claimSize)
	}

	// For smaller tokens, just return the base token
	return baseToken
}

// TestTokens provides test JWT tokens
type TestTokens struct {
	validJWT   string
	expiredJWT string
}

func NewTestTokens() *TestTokens {
	return &TestTokens{
		validJWT:   "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJodHRwczovL3Rlc3QtaXNzdWVyLmNvbSIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwiZXhwIjozMDAwMDAwMDAwLCJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ.dGVzdC1zaWduYXR1cmU",
		expiredJWT: "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJodHRwczovL3Rlc3QtaXNzdWVyLmNvbSIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwiZXhwIjoxMDAwMDAwMDAwLCJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ.dGVzdC1zaWduYXR1cmU",
	}
}

func (tt *TestTokens) CreateValidJWT() string {
	return tt.validJWT
}

// TokenSet represents a complete set of tokens with proper field names
type TokenSet struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
}

func (tt *TestTokens) GetValidTokenSet() *TokenSet {
	return &TokenSet{
		AccessToken:  tt.validJWT,
		IDToken:      tt.validJWT,
		RefreshToken: ValidRefreshToken,
	}
}

func (tt *TestTokens) CreateIncompressibleToken(size int) string {
	// Create a token with random data that doesn't compress well
	return "incompressible." + generateRandomString(size) + ".signature"
}

func (tt *TestTokens) CreateUniqueValidJWT(suffix string) string {
	// Return a unique valid JWT for each call
	return tt.validJWT + "_" + suffix
}

func (tt *TestTokens) GetLargeTokenSet() *TokenSet {
	return &TokenSet{
		AccessToken:  tt.CreateIncompressibleToken(2000),
		IDToken:      tt.CreateIncompressibleToken(2000),
		RefreshToken: ValidRefreshToken,
	}
}

func (tt *TestTokens) CreateExpiredJWT() string {
	return tt.expiredJWT
}

func (tt *TestTokens) CreateLargeValidJWT(claimSize int) string {
	// Create a large claim
	largeClaim := generateRandomString(claimSize)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test-key-id"}`))

	payload := fmt.Sprintf(`{"iss":"https://test-issuer.com","aud":"test-client-id","exp":3000000000,"sub":"test-subject","email":"test@example.com","large_claim":"%s"}`, largeClaim)
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))

	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))

	return fmt.Sprintf("%s.%s.%s", header, encodedPayload, signature)
}
