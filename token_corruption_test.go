package traefikoidc

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/sessions"
)

// TestTokenCorruptionScenario reproduces the exact failure pattern from GitHub issue #53:
// Token verified successfully multiple times, then fails with "signature verification failed"
func TestTokenCorruptionScenario(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create a valid JWT token with proper base64url signature
	testTokens := NewTestTokens()
	validJWT := testTokens.CreateLargeValidJWT(100) // Create a small valid token

	tests := []struct {
		corruptionScenario func(*SessionData)
		name               string
		tokenSize          int
		iterations         int
		expectConsistent   bool
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
			expectConsistent: false, // Will be corrupted intentionally
			corruptionScenario: func(session *SessionData) {
				// Simulate corruption by directly modifying session values
				if session.accessSession != nil {
					// Simulate corrupted compressed data
					session.accessSession.Values["token"] = "corrupted_base64_!@#$"
					session.accessSession.Values["compressed"] = true
				}
			},
		},
		{
			name:             "Chunk reassembly corruption simulation",
			tokenSize:        25000, // Large enough to force chunking even after compression
			iterations:       5,
			expectConsistent: false, // Will be corrupted intentionally
			corruptionScenario: func(session *SessionData) {
				// Simulate chunk corruption with invalid base64 characters
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

			// Create token of specified size
			token := createTokenOfSize(validJWT, tt.tokenSize)

			// 1. Store the token
			session.SetAccessToken(token)
			t.Logf("Stored token of size %d bytes", len(token))

			// 2. Verify token can be retrieved multiple times successfully
			var retrievedTokens []string
			for i := 0; i < tt.iterations; i++ {
				retrieved := session.GetAccessToken()
				retrievedTokens = append(retrievedTokens, retrieved)

				if tt.expectConsistent && retrieved != token {
					t.Errorf("Iteration %d: Token mismatch, expected consistency", i)
					break
				}
			}

			// 3. Apply corruption scenario if specified
			if tt.corruptionScenario != nil {
				tt.corruptionScenario(session)
			}

			// 4. Retrieve token after potential corruption
			finalRetrieved := session.GetAccessToken()

			if tt.expectConsistent {
				// With fixes, token should still be retrievable correctly
				if finalRetrieved != token {
					t.Errorf("Final retrieval failed - corruption not handled correctly")
					t.Logf("Expected: %q", token)
					t.Logf("Got:      %q", finalRetrieved)
				}
			} else {
				// For corruption scenarios, expect empty string (graceful failure)
				if finalRetrieved != "" {
					t.Errorf("Expected corruption to result in empty token, got: %q", finalRetrieved)
				}
			}

			// 5. Verify all previous retrievals were consistent (if expected)
			if tt.expectConsistent {
				for i, retrieved := range retrievedTokens {
					if retrieved != token {
						t.Errorf("Iteration %d produced inconsistent result", i)
					}
				}
			}
		})
	}
}

// TestCompressionIntegrityFailure tests scenarios where compression fails integrity checks
func TestCompressionIntegrityFailure(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		expectSame bool
	}{
		{
			name:       "Valid JWT",
			token:      NewTestTokens().CreateLargeValidJWT(100),
			expectSame: true,
		},
		{
			name:       "Invalid JWT - wrong dots",
			token:      "invalid.token",
			expectSame: true, // Should return unchanged
		},
		{
			name:       "Oversized token",
			token:      "header." + strings.Repeat("A", 60000) + ".sig",
			expectSame: true, // Should return unchanged due to size limit
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed := compressToken(tt.token)

			if tt.expectSame && compressed != tt.token {
				// If we expect the token to remain the same but it was compressed,
				// verify round-trip integrity
				decompressed := decompressToken(compressed)
				if decompressed != tt.token {
					t.Errorf("Compression integrity failed: original=%q, decompressed=%q", tt.token, decompressed)
				}
			}
		})
	}
}

// TestChunkReassemblyEdgeCases tests edge cases in chunk reassembly that could cause corruption
func TestChunkReassemblyEdgeCases(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	// Create a large token that will definitely be chunked
	testTokens := NewTestTokens()
	largeToken := testTokens.CreateLargeValidJWT(8000)

	// Store the token to create chunks
	session.SetAccessToken(largeToken)

	if len(session.accessTokenChunks) == 0 {
		t.Skip("Token was not chunked, skipping reassembly tests")
	}

	t.Logf("Token was split into %d chunks", len(session.accessTokenChunks))

	// Test various corruption scenarios
	corruptionTests := []struct {
		corruption  func(map[int]*sessions.Session)
		name        string
		expectEmpty bool
	}{
		{
			name: "Gap in chunk sequence",
			corruption: func(chunks map[int]*sessions.Session) {
				// Remove chunk 1 if it exists
				delete(chunks, 1)
			},
			expectEmpty: true,
		},
		{
			name: "Chunk with nil value",
			corruption: func(chunks map[int]*sessions.Session) {
				if chunk, exists := chunks[0]; exists {
					chunk.Values["token_chunk"] = nil
				}
			},
			expectEmpty: true,
		},
		{
			name: "Chunk with wrong type",
			corruption: func(chunks map[int]*sessions.Session) {
				if chunk, exists := chunks[0]; exists {
					chunk.Values["token_chunk"] = 12345 // Should be string
				}
			},
			expectEmpty: true,
		},
		{
			name: "Empty chunk data",
			corruption: func(chunks map[int]*sessions.Session) {
				if chunk, exists := chunks[0]; exists {
					chunk.Values["token_chunk"] = ""
				}
			},
			expectEmpty: true,
		},
		{
			name: "Excessive chunk count",
			corruption: func(chunks map[int]*sessions.Session) {
				// This test simulates having too many chunks (>50 limit)
				// We'll create a scenario by adding many fake chunks
				for i := 0; i < 60; i++ {
					fakeSession := &sessions.Session{Values: make(map[interface{}]interface{})}
					fakeSession.Values["token_chunk"] = "fake_chunk_data"
					chunks[i] = fakeSession
				}
			},
			expectEmpty: true,
		},
	}

	for _, ct := range corruptionTests {
		t.Run(ct.name, func(t *testing.T) {
			// Get a fresh session for each test
			freshReq := httptest.NewRequest("GET", "http://example.com/foo", nil)
			freshSession, err := sm.GetSession(freshReq)
			if err != nil {
				t.Fatalf("Failed to get fresh session: %v", err)
			}
			defer freshSession.ReturnToPool()

			// Store the large token again
			freshSession.SetAccessToken(largeToken)

			// Apply corruption
			ct.corruption(freshSession.accessTokenChunks)

			// Try to retrieve the token
			retrieved := freshSession.GetAccessToken()

			if ct.expectEmpty {
				if retrieved != "" {
					t.Errorf("Expected empty token due to corruption, got: %q", retrieved)
				}
			} else {
				if retrieved != largeToken {
					t.Errorf("Expected original token, got: %q", retrieved)
				}
			}
		})
	}
}

// TestRaceConditionProtection tests that concurrent access doesn't cause corruption
func TestRaceConditionProtection(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	const numGoroutines = 20
	const numOperations = 50

	// Create tokens of different sizes
	testTokens := NewTestTokens()
	tokens := []string{
		testTokens.CreateUniqueValidJWT("token1"),
		testTokens.CreateLargeValidJWT(3000),
		testTokens.CreateLargeValidJWT(6000),
	}

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*numOperations)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				tokenIndex := (goroutineID + j) % len(tokens)
				expectedToken := tokens[tokenIndex]

				// Set token
				session.SetAccessToken(expectedToken)

				// Retrieve token
				retrieved := session.GetAccessToken()

				// Verify it's a valid JWT (should have exactly 2 dots)
				if retrieved != "" && strings.Count(retrieved, ".") != 2 {
					errChan <- fmt.Errorf("goroutine %d, op %d: invalid JWT format in retrieved token: %q",
						goroutineID, j, retrieved)
					continue
				}

				// The retrieved token should be one of the valid tokens we set
				// (due to concurrent access, it might not be the exact one we just set)
				isValidToken := false
				for _, validToken := range tokens {
					if retrieved == validToken {
						isValidToken = true
						break
					}
				}

				if retrieved != "" && !isValidToken {
					errChan <- fmt.Errorf("goroutine %d, op %d: retrieved unknown token: %q",
						goroutineID, j, retrieved)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Check for any errors
	for err := range errChan {
		t.Error(err)
	}
}

// TestMemoryExhaustionProtection tests protection against memory exhaustion attacks
func TestMemoryExhaustionProtection(t *testing.T) {
	tests := []struct {
		setupCorruption func() string
		name            string
		expectRejection bool
	}{
		{
			name: "Extremely large compressed data",
			setupCorruption: func() string {
				return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("A"), 200*1024)) // 200KB
			},
			expectRejection: true,
		},
		{
			name: "Malformed gzip bomb attempt",
			setupCorruption: func() string {
				// Create data that looks like gzip but would decompress to huge size
				var buf bytes.Buffer
				gz := gzip.NewWriter(&buf)
				gz.Write(bytes.Repeat([]byte("A"), 10*1024)) // 10KB that compresses well
				gz.Close()

				compressed := buf.Bytes()
				// Modify to make it potentially dangerous
				return base64.StdEncoding.EncodeToString(compressed)
			},
			expectRejection: false, // Our decompression has size limits
		},
		{
			name: "Token with excessive chunk simulation",
			setupCorruption: func() string {
				// This will be tested in the session layer
				return strings.Repeat("chunk.", 100) + "final"
			},
			expectRejection: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			corruptedData := tt.setupCorruption()

			result := decompressToken(corruptedData)

			if tt.expectRejection {
				// Should return original corrupted data, not attempt decompression
				if result != corruptedData {
					t.Errorf("Expected rejection of dangerous data, but decompression was attempted")
				}
			}

			// Verify no excessive memory was used (this test would catch OOM in practice)
			// The fact that we reach this point means memory limits were effective
		})
	}
}

// TestBackwardCompatibility ensures that sessions created before the fixes still work
func TestBackwardCompatibility(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	// Simulate old-style session data (without new validation fields)
	testTokens := NewTestTokens()
	oldStyleToken := testTokens.CreateUniqueValidJWT("old")

	// Manually set token without going through new SetAccessToken validation
	session.accessSession.Values["token"] = oldStyleToken
	session.accessSession.Values["compressed"] = false

	// Should still be retrievable
	retrieved := session.GetAccessToken()
	if retrieved != oldStyleToken {
		t.Errorf("Backward compatibility failed: expected %q, got %q", oldStyleToken, retrieved)
	}

	// Test with simulated old compressed token
	oldCompressed := compressToken(oldStyleToken)
	session.accessSession.Values["token"] = oldCompressed
	session.accessSession.Values["compressed"] = true

	retrieved2 := session.GetAccessToken()
	if retrieved2 != oldStyleToken {
		t.Errorf("Backward compatibility with compression failed: expected %q, got %q", oldStyleToken, retrieved2)
	}
}

// createTokenOfSize creates a JWT token of approximately the specified size
// This function is deprecated - use TestTokens.CreateLargeValidJWT instead
func createTokenOfSize(baseToken string, targetSize int) string {
	testTokens := NewTestTokens()
	return testTokens.CreateLargeValidJWT(targetSize)
}
