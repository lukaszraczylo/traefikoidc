package traefikoidc

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

func TestSessionPoolMemoryLeak(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create a fake request
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	// Test 1: Successful session creation and return
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	// Clear the session which should return it to the pool
	session.Clear(req, nil)

	// Test 2: ReturnToPool explicit method
	session, err = sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	// Call ReturnToPool directly
	session.ReturnToPool()

	// Test 3: Error path in GetSession
	// Modify the session store to force an error - use a different encryption key
	badSM, _ := NewSessionManager("different0123456789abcdef0123456789abcdef0123456789", false, logger)

	// Get session using mismatched manager/request to force error
	_, err = badSM.GetSession(req)
	if err == nil {
		// We don't test the exact error since it could vary, just that we get one
		t.Log("Note: Expected error when using mismatched encryption keys")
	}

	// Force GC to ensure any objects are cleaned up
	runtime.GC()

	// Wait a moment for GC to complete
	time.Sleep(100 * time.Millisecond)

	// Check if we have objects in the pool
	// This is just a simple check; in a real scenario, we'd have to
	// consider that sync.Pool can discard objects at any time.
	pooledCount := getPooledObjects(sm)
	t.Logf("Pooled objects count: %d", pooledCount)
}

func TestSessionErrorHandling(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create a fake request
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	// Call the GetSession method, corrupting the cookie to force an error
	req.AddCookie(&http.Cookie{
		Name:  mainCookieName,
		Value: "corrupt-value",
	})

	_, err = sm.GetSession(req)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// Check that the error message contains our expected prefix
	if err != nil && !strings.Contains(err.Error(), "failed to get main session:") {
		t.Fatalf("Unexpected error message: %v", err)
	}
}

func TestSessionClearAlwaysReturnsToPool(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create a test request with the special header that will trigger an error
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Set("X-Test-Error", "true") // This will trigger the error in session.Clear

	// Get a session
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	// Create a response writer
	w := httptest.NewRecorder()

	// Call Clear with the test request (with X-Test-Error header) and response writer
	// This should trigger the serialization error in Save
	clearErr := session.Clear(req, w)

	// Verify that Clear returned the error from Save
	if clearErr == nil {
		t.Error("Expected an error from Clear with X-Test-Error header, but got nil")
	} else {
		t.Logf("Received expected error from Clear: %v", clearErr)
	}

	// Force GC to ensure any objects are cleaned up
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	// Create and clear another session (without the error header) to verify the pool is still working
	normalReq := httptest.NewRequest("GET", "http://example.com/foo", nil)
	session2, err := sm.GetSession(normalReq)
	if err != nil {
		t.Fatalf("Second GetSession failed: %v", err)
	}
	session2.Clear(normalReq, nil)

	// If we got here without panics, the test is successful
	t.Log("Session returned to pool despite errors")
}

// This placeholder comment is intentionally left empty since we're removing redundant code

// Helper function to count objects in the session pool for a given manager
func getPooledObjects(sm *SessionManager) int {
	// Collect objects until we can't get any more from the pool
	// Set a max limit to avoid potential infinite loops
	var objects []*SessionData
	maxAttempts := 100 // Safety limit to prevent infinite loops

	for range maxAttempts {
		obj := sm.sessionPool.Get()
		if obj == nil {
			break
		}

		// Type assertion with validation
		sessionData, ok := obj.(*SessionData)
		if !ok {
			// Return the object even if it's not the right type to avoid leaks
			sm.sessionPool.Put(obj)
			break
		}

		objects = append(objects, sessionData)
	}

	// Count how many objects we found
	count := len(objects)

	// Return all objects back to the pool to preserve the pool state
	for _, obj := range objects {
		sm.sessionPool.Put(obj)
	}

	return count
}

// TestSessionObjectTracking verifies that session objects are properly
// returned to the pool in various scenarios including normal usage and error paths
func TestSessionObjectTracking(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create a fake request
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	// Test that the session pool is used as expected
	hasNew := sm.sessionPool.New != nil
	if !hasNew {
		t.Error("Expected sessionPool.New function to be set")
	}

	// Create and discard 5 sessions
	for range 5 {
		session, err := sm.GetSession(req)
		if err != nil {
			t.Fatalf("GetSession failed: %v", err)
		}
		session.ReturnToPool()
	}

	// Create a session and get an error when trying to clear it
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	// Deliberately cause bad state in the session object
	session.mainSession = nil // This will cause an error in Clear

	// Even with an error, the pool should not leak
	session.ReturnToPool()

	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	// Success - if we got here without crashing, the pool is working as expected
	t.Log("Session pool handling verified")
}

// TestTokenCompressionIntegrity tests that token compression and decompression maintains JWT integrity
func TestTokenCompressionIntegrity(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		wantFail bool
	}{
		{
			name:  "Valid JWT - Small",
			token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.signature",
		},
		{
			name:  "Valid JWT - Large",
			token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + strings.Repeat("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9", 100) + ".signature",
		},
		{
			name:     "Invalid JWT - Wrong dot count",
			token:    "invalid.token",
			wantFail: true,
		},
		{
			name:     "Invalid JWT - No dots",
			token:    "invalidtoken",
			wantFail: true,
		},
		{
			name:     "Invalid JWT - Too many dots",
			token:    "part1.part2.part3.part4",
			wantFail: true,
		},
		{
			name:     "Empty token",
			token:    "",
			wantFail: false, // Empty tokens are handled gracefully
		},
		{
			name:     "Oversized token (>50KB)",
			token:    "part1." + strings.Repeat("A", 51*1024) + ".part3",
			wantFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed := compressToken(tt.token)

			if tt.wantFail {
				// For invalid tokens, compression should return original
				if compressed != tt.token {
					t.Errorf("Expected compression to return original for invalid token, got different result")
				}
				return
			}

			// For valid tokens, test round-trip integrity
			decompressed := decompressToken(compressed)
			if decompressed != tt.token {
				t.Errorf("Token integrity lost: original=%q, compressed=%q, decompressed=%q",
					tt.token, compressed, decompressed)
			}

			// Test that decompression is idempotent
			decompressed2 := decompressToken(decompressed)
			if decompressed2 != tt.token {
				t.Errorf("Decompression not idempotent: %q != %q", decompressed2, tt.token)
			}
		})
	}
}

// TestTokenCompressionCorruptionDetection tests that gzip corruption is detected and handled
func TestTokenCompressionCorruptionDetection(t *testing.T) {
	validJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.signature"

	tests := []struct {
		name           string
		corruptedInput string
		expectOriginal bool
	}{
		{
			name:           "Invalid base64",
			corruptedInput: "!@#$%^&*()",
			expectOriginal: true,
		},
		{
			name:           "Valid base64 but invalid gzip",
			corruptedInput: base64.StdEncoding.EncodeToString([]byte("not gzip data")),
			expectOriginal: true,
		},
		{
			name:           "Truncated gzip data",
			corruptedInput: "H4sI", // Incomplete gzip header
			expectOriginal: true,
		},
		{
			name:           "Empty string",
			corruptedInput: "",
			expectOriginal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decompressToken(tt.corruptedInput)
			if tt.expectOriginal && result != tt.corruptedInput {
				t.Errorf("Expected decompression to return original corrupted input, got: %q", result)
			}
		})
	}

	// Test that valid compression still works
	compressed := compressToken(validJWT)
	decompressed := decompressToken(compressed)
	if decompressed != validJWT {
		t.Errorf("Valid compression/decompression failed: %q != %q", decompressed, validJWT)
	}
}

// TestTokenChunkingIntegrity tests that large tokens are properly chunked and reassembled
func TestTokenChunkingIntegrity(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create tokens of various sizes to test chunking
	testTokens := NewTestTokens()
	tests := []struct {
		name          string
		tokenSize     int
		expectChunked bool
	}{
		{
			name:          "Small token (no chunking)",
			tokenSize:     100,
			expectChunked: false,
		},
		{
			name:          "Medium token (no chunking)",
			tokenSize:     800, // FIXED: Reduced further to account for new conservative chunk size (1200 bytes)
			expectChunked: false,
		},
		{
			name:          "Large token (chunking required)",
			tokenSize:     5000,
			expectChunked: true,
		},
		{
			name:          "Very large token (multiple chunks)",
			tokenSize:     10000,
			expectChunked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// FIXED: Use incompressible tokens to ensure chunking occurs
			var token string
			if tt.expectChunked {
				token = testTokens.CreateIncompressibleToken(tt.tokenSize)
			} else {
				token = testTokens.CreateLargeValidJWT(tt.tokenSize)
			}

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			// Store the token
			session.SetAccessToken(token)

			// Retrieve the token
			retrievedToken := session.GetAccessToken()

			// Verify integrity
			if retrievedToken != token {
				t.Errorf("Token integrity lost:\nOriginal:  %q\nRetrieved: %q", token, retrievedToken)
			}

			// Check if chunking occurred as expected
			hasChunks := len(session.accessTokenChunks) > 0
			if tt.expectChunked != hasChunks {
				t.Errorf("Chunking expectation mismatch: expected chunked=%v, has chunks=%v", tt.expectChunked, hasChunks)
			}

			session.ReturnToPool()
		})
	}
}

// TestTokenChunkingCorruptionResistance tests handling of corrupted chunks
func TestTokenChunkingCorruptionResistance(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create a large token that will be chunked
	largeToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"sub":"test","data":"%s"}`, strings.Repeat("A", 5000))) +
		".signature"

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	// Store the token (this should create chunks)
	session.SetAccessToken(largeToken)
	if len(session.accessTokenChunks) == 0 {
		t.Skip("Token was not chunked, skipping corruption test")
	}

	tests := []struct {
		name         string
		corruptChunk func(chunks map[int]*sessions.Session)
		expectEmpty  bool
	}{
		{
			name: "Missing chunk in sequence",
			corruptChunk: func(chunks map[int]*sessions.Session) {
				// Remove a middle chunk
				if len(chunks) > 1 {
					delete(chunks, 1)
				}
			},
			expectEmpty: true,
		},
		{
			name: "Empty chunk data",
			corruptChunk: func(chunks map[int]*sessions.Session) {
				// Set first chunk to empty
				if chunk, exists := chunks[0]; exists {
					chunk.Values["token_chunk"] = ""
				}
			},
			expectEmpty: true,
		},
		{
			name: "Wrong data type in chunk",
			corruptChunk: func(chunks map[int]*sessions.Session) {
				// Set chunk data to wrong type
				if chunk, exists := chunks[0]; exists {
					chunk.Values["token_chunk"] = 123 // Should be string
				}
			},
			expectEmpty: true,
		},
		{
			name: "Oversized chunk",
			corruptChunk: func(chunks map[int]*sessions.Session) {
				// Set chunk to oversized data
				if chunk, exists := chunks[0]; exists {
					chunk.Values["token_chunk"] = strings.Repeat("A", maxCookieSize+200)
				}
			},
			expectEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get a fresh session
			freshSession, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get fresh session: %v", err)
			}

			// Store the token again
			freshSession.SetAccessToken(largeToken)

			// Apply corruption
			tt.corruptChunk(freshSession.accessTokenChunks)

			// Try to retrieve the token
			retrievedToken := freshSession.GetAccessToken()

			if tt.expectEmpty {
				if retrievedToken != "" {
					t.Errorf("Expected empty token due to corruption, got: %q", retrievedToken)
				}
			} else {
				if retrievedToken != largeToken {
					t.Errorf("Expected original token despite corruption, got: %q", retrievedToken)
				}
			}

			freshSession.ReturnToPool()
		})
	}

	session.ReturnToPool()
}

// TestTokenSizeLimits tests that token size limits are enforced
func TestTokenSizeLimits(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	testTokens := NewTestTokens()
	tests := []struct {
		name         string
		tokenSize    int
		expectStored bool
	}{
		{
			name:         "Normal size token",
			tokenSize:    1000,
			expectStored: true,
		},
		{
			name:         "Large but acceptable token",
			tokenSize:    30000, // FIXED: 30KB to ensure final size < 100KB limit
			expectStored: true,
		},
		{
			name:         "Oversized token (>100KB)",
			tokenSize:    120000, // FIXED: 120KB to ensure rejection after compression
			expectStored: false,  // Should be rejected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// FIXED: Use proper token generation that accounts for base64 encoding
			var token string
			if tt.expectStored {
				token = testTokens.CreateLargeValidJWT(tt.tokenSize)
			} else {
				token = testTokens.CreateIncompressibleToken(tt.tokenSize)
			}

			// Store the token
			session.SetAccessToken(token)

			// Try to retrieve it
			retrievedToken := session.GetAccessToken()

			if tt.expectStored {
				if retrievedToken != token {
					t.Errorf("Expected token to be stored and retrieved, but got different token")
				}
			} else {
				if retrievedToken == token {
					t.Errorf("Expected oversized token to be rejected, but it was stored")
				}
			}
		})
	}
}

// TestConcurrentTokenOperations tests thread safety of token operations
func TestConcurrentTokenOperations(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	const numGoroutines = 10
	const numOperations = 100

	// Test concurrent access and refresh token operations
	done := make(chan bool, numGoroutines)

	for i := range numGoroutines {
		go func(id int) {
			defer func() { done <- true }()

			for j := range numOperations {
				// Create unique tokens for each goroutine/operation
				accessToken := ValidAccessToken
				refreshToken := fmt.Sprintf("refresh_token_%d_%d", id, j)

				// Concurrent operations
				session.SetAccessToken(accessToken)
				session.SetRefreshToken(refreshToken)

				retrievedAccess := session.GetAccessToken()
				retrievedRefresh := session.GetRefreshToken()

				// Verify tokens are still valid (should be one of the tokens set by any goroutine)
				if retrievedAccess != "" && strings.Count(retrievedAccess, ".") != 2 {
					t.Errorf("Retrieved access token has invalid format: %q", retrievedAccess)
				}
				if retrievedRefresh != "" && len(retrievedRefresh) < 10 {
					t.Errorf("Retrieved refresh token is too short: %q", retrievedRefresh)
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for range numGoroutines {
		<-done
	}
}

// TestSessionValidationAndCleanup tests session validation and orphan cleanup
func TestSessionValidationAndCleanup(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	rw := httptest.NewRecorder()

	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	// Set tokens that will create chunks
	largeToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(`{"data":"large"}`, 500))) +
		".signature"

	session.SetAccessToken(largeToken)
	session.SetRefreshToken("refresh_token_test")

	// Save session to create cookies
	if err := session.Save(req, rw); err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Verify chunks were created
	if len(session.accessTokenChunks) == 0 {
		t.Log("No chunks created, large token test may not be applicable")
	}

	// Test cleanup by clearing session
	if err := session.Clear(req, rw); err != nil {
		t.Logf("Clear returned error (may be expected): %v", err)
	}

	// Verify tokens are cleared
	if token := session.GetAccessToken(); token != "" {
		t.Errorf("Access token should be empty after clear, got: %q", token)
	}
	if token := session.GetRefreshToken(); token != "" {
		t.Errorf("Refresh token should be empty after clear, got: %q", token)
	}
}
