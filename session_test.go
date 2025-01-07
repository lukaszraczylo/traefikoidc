package traefikoidc

import (
	"math/rand"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func init() {
	// Initialize random seed
	rand.Seed(time.Now().UnixNano())
}

// generateRandomString creates a random string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// TestTokenCompression tests the token compression functionality
func TestTokenCompression(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		wantSize int // Expected size after compression (approximate)
	}{
		{
			name:     "Short token",
			token:    "shorttoken",
			wantSize: 50, // Base64 encoded gzip has overhead for small content
		},
		{
			name:     "Repeating content",
			token:    strings.Repeat("abcdef", 1000),
			wantSize: 100, // Should compress well due to repetition
		},
		{
			name:     "Random content",
			token:    generateRandomString(1000),
			wantSize: 2000, // Random content won't compress much
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed := compressToken(tt.token)
			decompressed := decompressToken(compressed)

			// Only verify compression ratio for non-short tokens
			if len(tt.token) > 100 {
				compressionRatio := float64(len(compressed)) / float64(len(tt.token))
				t.Logf("Compression ratio for %s: %.2f", tt.name, compressionRatio)
				
				if compressionRatio > 1.1 { // Allow up to 10% size increase
					t.Errorf("Compression increased size too much: original=%d, compressed=%d, ratio=%.2f", 
						len(tt.token), len(compressed), compressionRatio)
				}
			}

			// Verify decompression restores original
			if decompressed != tt.token {
				t.Error("Decompression failed to restore original token")
			}

			// Verify approximate compression ratio
			if len(compressed) > tt.wantSize*2 {
				t.Errorf("Compression ratio worse than expected: got=%d, want<%d", len(compressed), tt.wantSize*2)
			}
		})
	}
}

// TestSessionManager tests the SessionManager functionality
func TestSessionManager(t *testing.T) {
	ts := &TestSuite{t: t}
	ts.Setup()

	tests := []struct {
		name                string
		authenticated       bool
		email              string
		accessToken        string
		refreshToken       string
		expectedCookieCount int
		wantCompressed     bool // Whether tokens should be compressed
	}{
		{
			name:                "Short tokens",
			authenticated:       true,
			email:              "test@example.com",
			accessToken:        "shortaccesstoken",
			refreshToken:       "shortrefreshtoken",
			expectedCookieCount: 3, // main, access, refresh
			wantCompressed:     true,
		},
		{
			name:          "Long tokens exceeding 4096 bytes",
			authenticated: true,
			email:         "test@example.com",
			accessToken:   strings.Repeat("x", 5000),
			refreshToken:  strings.Repeat("y", 6000),
			expectedCookieCount: calculateExpectedCookieCount(strings.Repeat("x", 5000), strings.Repeat("y", 6000)),
			wantCompressed:     true,
		},
		{
			name:          "REALLY long tokens, exceeding 25000 bytes",
			authenticated: true,
			email:         "test@example.com",
			accessToken:   strings.Repeat("x", 25000),
			refreshToken:  strings.Repeat("y", 25000),
			expectedCookieCount: calculateExpectedCookieCount(strings.Repeat("x", 25000), strings.Repeat("y", 25000)),
			wantCompressed:     true,
		},
		{
			name:                "Unauthenticated session",
			authenticated:       false,
			email:              "",
			accessToken:        "",
			refreshToken:       "",
			expectedCookieCount: 3, // main, access, refresh
			wantCompressed:     false,
		},
		{
			name:          "Random content tokens",
			authenticated: true,
			email:         "test@example.com",
			accessToken:   generateRandomString(5000),
			refreshToken:  generateRandomString(5000),
			expectedCookieCount: calculateExpectedCookieCount(generateRandomString(5000), generateRandomString(5000)),
			wantCompressed:     true,
		},
	}

	for _, tc := range tests {
			tc := tc // Capture range variable
			t.Run(tc.name, func(t *testing.T) {
					req := httptest.NewRequest("GET", "/test", nil)
					rr := httptest.NewRecorder()

					session, err := ts.sessionManager.GetSession(req)
					if err != nil {
							t.Fatalf("Failed to get session: %v", err)
					}

					// Set session values
					session.SetAuthenticated(tc.authenticated)
					session.SetEmail(tc.email)
					session.SetAccessToken(tc.accessToken)
					session.SetRefreshToken(tc.refreshToken)

					// Save session
					if err := session.Save(req, rr); err != nil {
							t.Fatalf("Failed to save session: %v", err)
					}

					// Verify cookies are set and compression is used when appropriate
					cookies := rr.Result().Cookies()
					if len(cookies) != tc.expectedCookieCount {
						t.Errorf("Expected %d cookies, got %d", tc.expectedCookieCount, len(cookies))
					}

					// Verify compression is working by checking token sizes
					for _, cookie := range cookies {
						if strings.Contains(cookie.Name, accessTokenCookie) {
							// Get original and stored sizes
							originalSize := len(tc.accessToken)
							storedSize := len(cookie.Value)
							
							if originalSize > 100 && tc.wantCompressed {
								// For large tokens, verify some compression occurred
								compressionRatio := float64(storedSize) / float64(originalSize)
								t.Logf("Access token compression ratio: %.2f (original: %d, stored: %d)", 
									compressionRatio, originalSize, storedSize)
								
								if compressionRatio > 0.9 { // Allow some overhead, but should see compression
									t.Errorf("Expected compression for large token in cookie %s (ratio: %.2f)", 
										cookie.Name, compressionRatio)
								}
							}
						} else if strings.Contains(cookie.Name, refreshTokenCookie) {
							originalSize := len(tc.refreshToken)
							storedSize := len(cookie.Value)
							
							if originalSize > 100 && tc.wantCompressed {
								compressionRatio := float64(storedSize) / float64(originalSize)
								t.Logf("Refresh token compression ratio: %.2f (original: %d, stored: %d)", 
									compressionRatio, originalSize, storedSize)
								
								if compressionRatio > 0.9 {
									t.Errorf("Expected compression for large token in cookie %s (ratio: %.2f)", 
										cookie.Name, compressionRatio)
								}
							}
						}
					}

					// Create a new request with the cookies
					newReq := httptest.NewRequest("GET", "/test", nil)
					for _, cookie := range cookies {
							newReq.AddCookie(cookie)
					}

					// Get the session again and verify values
					newSession, err := ts.sessionManager.GetSession(newReq)
					if err != nil {
						t.Fatalf("Failed to get new session: %v", err)
					}

					// Verify session values
					if newSession.GetAuthenticated() != tc.authenticated {
						t.Errorf("Authentication status not preserved")
					}
					if email := newSession.GetEmail(); email != tc.email {
						t.Errorf("Expected email %s, got %s", tc.email, email)
					}
					if token := newSession.GetAccessToken(); token != tc.accessToken {
						t.Errorf("Access token not preserved: got len=%d, want len=%d", len(token), len(tc.accessToken))
					}
					if token := newSession.GetRefreshToken(); token != tc.refreshToken {
						t.Errorf("Refresh token not preserved: got len=%d, want len=%d", len(token), len(tc.refreshToken))
					}

					// Verify session pooling by checking if the session is reused
					session2, _ := ts.sessionManager.GetSession(newReq)
					if session2 == newSession {
						t.Error("Session not properly pooled")
					}
			})
	}
}

func calculateExpectedCookieCount(accessToken, refreshToken string) int {
	count := 3 // main, access, refresh

	// Helper to calculate chunks for compressed token
	calculateChunks := func(token string) int {
		// Compress token (matching the actual implementation)
		compressed := compressToken(token)
		
		// If compressed token fits in one cookie, no additional chunks needed
		if len(compressed) <= maxCookieSize {
			return 0
		}
		
		// Calculate chunks needed for compressed token
		return len(splitIntoChunks(compressed, maxCookieSize))
	}

	// Add chunks for access token if needed
	accessChunks := calculateChunks(accessToken)
	if accessChunks > 0 {
		count += accessChunks
	}

	// Add chunks for refresh token if needed
	refreshChunks := calculateChunks(refreshToken)
	if refreshChunks > 0 {
		count += refreshChunks
	}

	return count
}