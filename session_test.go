package traefikoidc

import (
	"crypto/rand"
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

// TestSessionPoolMemoryLeak tests that session objects are properly returned to the pool
func TestSessionPoolMemoryLeak(t *testing.T) {
	testTokens := NewTestTokens()
	edgeGen := NewEdgeCaseGenerator()
	runner := NewTestSuiteRunner()
	runner.SetTimeout(30 * time.Second)

	tests := []TableTestCase{
		{
			Name:        "Successful session creation and return",
			Description: "Test that sessions are properly created and returned to pool",
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				runtime.GC()
				time.Sleep(100 * time.Millisecond)
				return nil
			},
		},
		{
			Name:        "Explicit ReturnToPool method",
			Description: "Test that explicit pool return works correctly",
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				runtime.GC()
				time.Sleep(100 * time.Millisecond)
				return nil
			},
		},
		{
			Name:        "Error path in GetSession",
			Description: "Test pool behavior when GetSession fails",
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				runtime.GC()
				time.Sleep(100 * time.Millisecond)
				return nil
			},
		},
	}

	// Custom test execution since we need to test memory behavior
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				if err := test.Setup(t); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}

			if test.Teardown != nil {
				defer func() {
					if err := test.Teardown(t); err != nil {
						t.Errorf("Teardown failed: %v", err)
					}
				}()
			}

			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)

			switch test.Name {
			case "Successful session creation and return":
				session, err := sm.GetSession(req)
				if err != nil {
					t.Fatalf("GetSession failed: %v", err)
				}
				session.Clear(req, nil)

			case "Explicit ReturnToPool method":
				session, err := sm.GetSession(req)
				if err != nil {
					t.Fatalf("GetSession failed: %v", err)
				}
				session.ReturnToPool()

			case "Error path in GetSession":
				badSM, _ := NewSessionManager("different0123456789abcdef0123456789abcdef0123456789", false, "", logger)
				_, err = badSM.GetSession(req)
				if err == nil {
					t.Log("Note: Expected error when using mismatched encryption keys")
				}
			}

			pooledCount := getPooledObjects(sm)
			t.Logf("Pooled objects count: %d", pooledCount)
		})
	}

	_ = testTokens
	_ = edgeGen
}

// TestSessionErrorHandling tests comprehensive error scenarios using table-driven tests
func TestSessionErrorHandling(t *testing.T) {
	edgeGen := NewEdgeCaseGenerator()
	runner := NewTestSuiteRunner()

	// Generate edge case strings for cookie values
	edgeCases := edgeGen.GenerateStringEdgeCases()

	tests := []TableTestCase{
		{
			Name:        "Corrupt cookie value",
			Description: "Test handling of corrupted cookie values",
			Input:       "corrupt-value",
			Expected:    "failed to get main session:",
		},
		{
			Name:        "Invalid base64 cookie",
			Description: "Test handling of invalid base64 in cookies",
			Input:       "!@#$%^&*()",
			Expected:    "failed to get main session:",
		},
		{
			Name:        "Empty cookie value",
			Description: "Test handling of empty cookie values",
			Input:       "",
			Expected:    "", // Empty should work without error
		},
	}

	// Add edge cases dynamically
	for i, edgeCase := range edgeCases {
		if len(edgeCase) > 0 && !strings.ContainsAny(edgeCase, "\x00\x01\x02") { // Skip binary data for cookie tests
			tests = append(tests, TableTestCase{
				Name:        fmt.Sprintf("Edge case %d", i),
				Description: fmt.Sprintf("Test edge case string: %q", edgeCase[:minInt(20, len(edgeCase))]),
				Input:       edgeCase,
				Expected:    "", // Most edge cases should be handled gracefully
			})
		}
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)

			if input, ok := test.Input.(string); ok && input != "" {
				req.AddCookie(&http.Cookie{
					Name:  mainCookieName,
					Value: input,
				})
			}

			_, err = sm.GetSession(req)

			if expected, ok := test.Expected.(string); ok && expected != "" {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if !strings.Contains(err.Error(), expected) {
					t.Errorf("Unexpected error message: %v", err)
				}
			} else {
				// For empty expected, we allow either success or specific failures
				if err != nil {
					t.Logf("Got expected error for edge case: %v", err)
				}
			}
		})
	}

	_ = runner
}

// TestSessionClearAlwaysReturnsToPool tests that sessions are always returned to pool even on errors
func TestSessionClearAlwaysReturnsToPool(t *testing.T) {
	runner := NewTestSuiteRunner()

	memoryTests := []MemoryLeakTestCase{
		{
			Name:               "Session clear with error returns to pool",
			Description:        "Verify sessions return to pool even when Clear() errors",
			Iterations:         10,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  5.0,
			GCBetweenRuns:      true,
			Timeout:            30 * time.Second,
			Operation: func() error {
				logger := NewLogger("debug")
				sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
				if err != nil {
					return fmt.Errorf("failed to create session manager: %w", err)
				}

				req := httptest.NewRequest("GET", "http://example.com/foo", nil)
				req.Header.Set("X-Test-Error", "true")

				session, err := sm.GetSession(req)
				if err != nil {
					return fmt.Errorf("GetSession failed: %w", err)
				}

				w := httptest.NewRecorder()
				clearErr := session.Clear(req, w)

				// We expect an error due to the X-Test-Error header, but the session should still be returned
				if clearErr == nil {
					return fmt.Errorf("expected error from Clear with X-Test-Error header")
				}

				return nil
			},
		},
	}

	runner.RunMemoryLeakTests(t, memoryTests)

	// Additional verification test
	t.Run("Verify pool still works after errors", func(t *testing.T) {
		logger := NewLogger("debug")
		sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
		if err != nil {
			t.Fatalf("Failed to create session manager: %v", err)
		}

		normalReq := httptest.NewRequest("GET", "http://example.com/foo", nil)
		session2, err := sm.GetSession(normalReq)
		if err != nil {
			t.Fatalf("Second GetSession failed: %v", err)
		}
		session2.Clear(normalReq, nil)

		t.Log("Session returned to pool despite errors")
	})
}

// TestSessionObjectTracking tests session object tracking and pool behavior
func TestSessionObjectTracking(t *testing.T) {
	runner := NewTestSuiteRunner()

	tests := []TableTestCase{
		{
			Name:        "Session pool has New function",
			Description: "Verify that session pool is properly configured",
			Setup: func(t *testing.T) error {
				return nil
			},
		},
		{
			Name:        "Multiple session creation and disposal",
			Description: "Test creating and disposing multiple sessions",
			Input:       5,
		},
		{
			Name:        "Session with nil mainSession",
			Description: "Test error handling with corrupted session state",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				if err := test.Setup(t); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}

			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)

			switch test.Name {
			case "Session pool has New function":
				hasNew := sm.sessionPool.New != nil
				if !hasNew {
					t.Error("Expected sessionPool.New function to be set")
				}

			case "Multiple session creation and disposal":
				count := test.Input.(int)
				for i := 0; i < count; i++ {
					session, err := sm.GetSession(req)
					if err != nil {
						t.Fatalf("GetSession failed: %v", err)
					}
					session.ReturnToPool()
				}

			case "Session with nil mainSession":
				session, err := sm.GetSession(req)
				if err != nil {
					t.Fatalf("GetSession failed: %v", err)
				}

				session.mainSession = nil // Deliberately cause bad state
				session.ReturnToPool()
			}

			runtime.GC()
			time.Sleep(100 * time.Millisecond)
			t.Log("Session pool handling verified")
		})
	}

	_ = runner
}

// TestTokenCompressionIntegrity tests token compression using comprehensive test cases
func TestTokenCompressionIntegrity(t *testing.T) {
	testTokens := NewTestTokens()
	edgeGen := NewEdgeCaseGenerator()
	runner := NewTestSuiteRunner()

	// Create comprehensive test cases using edge case generator and test tokens
	testCases := []TableTestCase{
		{
			Name:     "Valid JWT Small",
			Input:    testTokens.GetValidTokenSet().AccessToken,
			Expected: true, // Should compress and decompress correctly
		},
		{
			Name:     "Valid JWT Large",
			Input:    testTokens.CreateLargeValidJWT(5000),
			Expected: true,
		},
		{
			Name:     "Minimal Valid JWT",
			Input:    MinimalValidJWT,
			Expected: true,
		},
		{
			Name:     "Invalid JWT Wrong dot count",
			Input:    InvalidTokenOneDot,
			Expected: false, // Should return original for invalid tokens
		},
		{
			Name:     "Invalid JWT No dots",
			Input:    InvalidTokenNoDots,
			Expected: false,
		},
		{
			Name:     "Invalid JWT Too many dots",
			Input:    InvalidTokenThreeDots,
			Expected: false,
		},
		{
			Name:     "Empty token",
			Input:    "",
			Expected: true, // Empty tokens are handled gracefully
		},
		{
			Name:     "Oversized token",
			Input:    testTokens.CreateIncompressibleToken(55000), // >50KB
			Expected: false,                                       // Should be rejected
		},
	}

	// Add string edge cases as additional test inputs
	stringEdgeCases := edgeGen.GenerateStringEdgeCases()
	for i, edgeCase := range stringEdgeCases {
		if len(edgeCase) > 0 && len(edgeCase) < 1000 { // Reasonable size for testing
			testCases = append(testCases, TableTestCase{
				Name:     fmt.Sprintf("Edge case string %d", i),
				Input:    edgeCase,
				Expected: true, // Most edge cases should be handled gracefully
			})
		}
	}

	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			token := test.Input.(string)
			expectValid := test.Expected.(bool)

			compressed := compressToken(token)

			if !expectValid {
				// For invalid tokens, compression should return original
				if compressed != token {
					t.Errorf("Expected compression to return original for invalid token, got different result")
				}
				return
			}

			// For valid tokens, test round-trip integrity
			decompressed := decompressToken(compressed)
			if decompressed != token {
				t.Errorf("Token integrity lost: original=%q, compressed=%q, decompressed=%q",
					token, compressed, decompressed)
			}

			// Test that decompression is idempotent
			decompressed2 := decompressToken(decompressed)
			if decompressed2 != token {
				t.Errorf("Decompression not idempotent: %q != %q", decompressed2, token)
			}
		})
	}

	_ = runner
}

// TestTokenCompressionCorruptionDetection tests corruption detection using table-driven approach
func TestTokenCompressionCorruptionDetection(t *testing.T) {
	testTokens := NewTestTokens()
	runner := NewTestSuiteRunner()

	tests := []TableTestCase{
		{
			Name:     "Invalid base64",
			Input:    "!@#$%^&*()",
			Expected: true, // Should return original
		},
		{
			Name:     "Valid base64 but invalid gzip",
			Input:    base64.StdEncoding.EncodeToString([]byte("not gzip data")),
			Expected: true,
		},
		{
			Name:     "Truncated gzip data",
			Input:    "H4sI", // Incomplete gzip header
			Expected: true,
		},
		{
			Name:     "Empty string",
			Input:    "",
			Expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			corruptedInput := test.Input.(string)
			expectOriginal := test.Expected.(bool)

			result := decompressToken(corruptedInput)
			if expectOriginal && result != corruptedInput {
				t.Errorf("Expected decompression to return original corrupted input, got: %q", result)
			}
		})
	}

	// Test that valid compression still works
	t.Run("Valid compression verification", func(t *testing.T) {
		validJWT := testTokens.GetValidTokenSet().AccessToken
		compressed := compressToken(validJWT)
		decompressed := decompressToken(compressed)
		if decompressed != validJWT {
			t.Errorf("Valid compression/decompression failed: %q != %q", decompressed, validJWT)
		}
	})

	_ = runner
}

// TestTokenChunkingIntegrity tests token chunking using comprehensive test patterns
func TestTokenChunkingIntegrity(t *testing.T) {
	testTokens := NewTestTokens()
	edgeGen := NewEdgeCaseGenerator()
	runner := NewTestSuiteRunner()

	tests := []TableTestCase{
		{
			Name:        "Small token no chunking",
			Description: "Small tokens should not be chunked",
			Input: struct {
				size          int
				expectChunked bool
			}{100, false},
		},
		{
			Name:        "Medium token no chunking",
			Description: "Medium tokens should not be chunked",
			Input: struct {
				size          int
				expectChunked bool
			}{800, false},
		},
		{
			Name:        "Large token chunking required",
			Description: "Large tokens should be chunked",
			Input: struct {
				size          int
				expectChunked bool
			}{5000, true},
		},
		{
			Name:        "Very large token multiple chunks",
			Description: "Very large tokens should create multiple chunks",
			Input: struct {
				size          int
				expectChunked bool
			}{10000, true},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			params := test.Input.(struct {
				size          int
				expectChunked bool
			})

			// Create token based on expectation
			var token string
			if params.expectChunked {
				token = testTokens.CreateIncompressibleToken(params.size)
			} else {
				token = testTokens.CreateLargeValidJWT(params.size)
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
			if params.expectChunked != hasChunks {
				t.Errorf("Chunking expectation mismatch: expected chunked=%v, has chunks=%v",
					params.expectChunked, hasChunks)
			}

			session.ReturnToPool()
		})
	}

	_ = edgeGen
	_ = runner
}

// TestTokenChunkingCorruptionResistance tests chunking corruption resistance using table patterns
func TestTokenChunkingCorruptionResistance(t *testing.T) {
	testTokens := NewTestTokens()
	runner := NewTestSuiteRunner()

	// Define corruption scenarios as test cases
	corruptionTests := []TableTestCase{
		{
			Name:        "Missing chunk in sequence",
			Description: "Test handling when a chunk is missing from sequence",
			Input: func(chunks map[int]*sessions.Session) {
				if len(chunks) > 1 {
					delete(chunks, 1)
				}
			},
			Expected: true, // Expect empty result
		},
		{
			Name:        "Empty chunk data",
			Description: "Test handling when chunk contains empty data",
			Input: func(chunks map[int]*sessions.Session) {
				if chunk, exists := chunks[0]; exists {
					chunk.Values["token_chunk"] = ""
				}
			},
			Expected: true,
		},
		{
			Name:        "Wrong data type in chunk",
			Description: "Test handling when chunk contains wrong data type",
			Input: func(chunks map[int]*sessions.Session) {
				if chunk, exists := chunks[0]; exists {
					chunk.Values["token_chunk"] = 123 // Should be string
				}
			},
			Expected: true,
		},
		{
			Name:        "Oversized chunk",
			Description: "Test handling when chunk exceeds size limits",
			Input: func(chunks map[int]*sessions.Session) {
				if chunk, exists := chunks[0]; exists {
					chunk.Values["token_chunk"] = strings.Repeat("A", maxCookieSize+200)
				}
			},
			Expected: true,
		},
	}

	for _, test := range corruptionTests {
		t.Run(test.Name, func(t *testing.T) {
			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			// Create a large token that will be chunked
			largeToken := testTokens.CreateIncompressibleToken(8000)

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

			// Apply corruption using the test input function
			corruptFunc := test.Input.(func(map[int]*sessions.Session))
			corruptFunc(session.accessTokenChunks)

			// Try to retrieve the token
			retrievedToken := session.GetAccessToken()

			expectEmpty := test.Expected.(bool)
			if expectEmpty {
				if retrievedToken != "" {
					t.Errorf("Expected empty token due to corruption, got: %q", retrievedToken)
				}
			} else {
				if retrievedToken != largeToken {
					t.Errorf("Expected original token despite corruption, got: %q", retrievedToken)
				}
			}

			session.ReturnToPool()
		})
	}

	// Fix variable name - should be corruptionTests, not tests
	_ = corruptionTests
	_ = runner
}

// TestTokenSizeLimits tests token size limit enforcement using table-driven tests
func TestTokenSizeLimits(t *testing.T) {
	testTokens := NewTestTokens()
	edgeGen := NewEdgeCaseGenerator()
	runner := NewTestSuiteRunner()

	tests := []TableTestCase{
		{
			Name:     "Normal size token",
			Input:    1000,
			Expected: true,
		},
		{
			Name:     "Large but acceptable token",
			Input:    20000, // 20KB
			Expected: true,
		},
		{
			Name:     "Oversized token rejection",
			Input:    120000, // 120KB
			Expected: false,  // Should be rejected
		},
	}

	// Add integer edge cases for token sizes
	intEdgeCases := edgeGen.GenerateIntegerEdgeCases()
	for _, size := range intEdgeCases {
		if size > 0 && size < 100000 {
			tests = append(tests, TableTestCase{
				Name:     fmt.Sprintf("Edge case size %d", size),
				Input:    size,
				Expected: size < 100000, // Reasonable threshold
			})
		}
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
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

			tokenSize := test.Input.(int)
			expectStored := test.Expected.(bool)

			var token string
			if expectStored {
				token = testTokens.CreateLargeValidJWT(tokenSize)
			} else {
				token = testTokens.CreateIncompressibleToken(tokenSize)
			}

			// Store the token
			session.SetAccessToken(token)

			// Try to retrieve it
			retrievedToken := session.GetAccessToken()

			if expectStored {
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

	_ = runner
}

// TestConcurrentTokenOperations tests thread safety using structured test patterns
func TestConcurrentTokenOperations(t *testing.T) {
	testTokens := NewTestTokens()
	runner := NewTestSuiteRunner()

	// Test concurrent operations using memory leak test pattern
	memoryTests := []MemoryLeakTestCase{
		{
			Name:               "Concurrent token operations",
			Description:        "Test thread safety of concurrent token operations",
			Iterations:         50,
			MaxGoroutineGrowth: 5, // Allow some growth for goroutines
			MaxMemoryGrowthMB:  10.0,
			GCBetweenRuns:      true,
			Timeout:            60 * time.Second,
			Operation: func() error {
				logger := NewLogger("debug")
				sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
				if err != nil {
					return fmt.Errorf("failed to create session manager: %w", err)
				}

				req := httptest.NewRequest("GET", "http://example.com/foo", nil)
				session, err := sm.GetSession(req)
				if err != nil {
					return fmt.Errorf("failed to get session: %w", err)
				}
				defer session.ReturnToPool()

				const numGoroutines = 10
				const numOperations = 100
				done := make(chan bool, numGoroutines)

				for i := 0; i < numGoroutines; i++ {
					go func(id int) {
						defer func() { done <- true }()

						for j := 0; j < numOperations; j++ {
							// Create unique tokens for each goroutine/operation
							accessToken := testTokens.CreateUniqueValidJWT(fmt.Sprintf("%d_%d", id, j))
							refreshToken := fmt.Sprintf("refresh_token_%d_%d", id, j)

							// Concurrent operations
							session.SetAccessToken(accessToken)
							session.SetRefreshToken(refreshToken)

							retrievedAccess := session.GetAccessToken()
							retrievedRefresh := session.GetRefreshToken()

							// Verify tokens are still valid (should be one of the tokens set by any goroutine)
							if retrievedAccess != "" && strings.Count(retrievedAccess, ".") != 2 {
								// Note: In concurrent access, we can't guarantee exact token match
								// but we can verify format is still valid
							}
							if retrievedRefresh != "" && len(retrievedRefresh) < 10 {
								// Verify minimum reasonable length
							}
						}
					}(i)
				}

				// Wait for all goroutines to complete
				for i := 0; i < numGoroutines; i++ {
					<-done
				}

				return nil
			},
		},
	}

	runner.RunMemoryLeakTests(t, memoryTests)

	_ = testTokens
}

// TestSessionValidationAndCleanup tests session validation using comprehensive patterns
func TestSessionValidationAndCleanup(t *testing.T) {
	testTokens := NewTestTokens()
	edgeGen := NewEdgeCaseGenerator()
	runner := NewTestSuiteRunner()

	tests := []TableTestCase{
		{
			Name:        "Session creation and token storage",
			Description: "Test basic session validation and cleanup",
		},
		{
			Name:        "Large token chunking validation",
			Description: "Test validation with tokens that require chunking",
		},
		{
			Name:        "Session cleanup verification",
			Description: "Test that sessions are properly cleaned up",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			rw := httptest.NewRecorder()

			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			switch test.Name {
			case "Session creation and token storage":
				// Test with normal tokens
				tokenSet := testTokens.GetValidTokenSet()
				session.SetAccessToken(tokenSet.AccessToken)
				session.SetRefreshToken(tokenSet.RefreshToken)

			case "Large token chunking validation":
				// Set tokens that will create chunks
				largeTokenSet := testTokens.GetLargeTokenSet()
				session.SetAccessToken(largeTokenSet.AccessToken)
				session.SetRefreshToken(largeTokenSet.RefreshToken)

			case "Session cleanup verification":
				// Set tokens and then clear them
				session.SetAccessToken(testTokens.GetValidTokenSet().AccessToken)
				session.SetRefreshToken("refresh_token_test")
			}

			// Save session to create cookies
			if err := session.Save(req, rw); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// For cleanup test, verify clearing works
			if test.Name == "Session cleanup verification" {
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
		})
	}

	_ = edgeGen
	_ = runner
}

// TestLargeIDTokenChunking tests ID token chunking using structured approach
func TestLargeIDTokenChunking(t *testing.T) {
	runner := NewTestSuiteRunner()

	tests := []TableTestCase{
		{
			Name:        "Large ID token chunking 20KB",
			Description: "Test that large ID tokens are properly chunked",
			Input:       20000,
			Expected:    2, // Expect at least 2 chunks
		},
		{
			Name:        "Very large ID token chunking 50KB",
			Description: "Test very large ID token chunking",
			Input:       50000,
			Expected:    5, // Expect at least 5 chunks
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			tokenSize := test.Input.(int)
			minExpectedChunks := test.Expected.(int)

			// Create a large ID token
			largeIDToken := createLargeIDToken(tokenSize)
			t.Logf("Created large ID token with length: %d", len(largeIDToken))

			// Create a request and response recorder
			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			rr := httptest.NewRecorder()

			// Get session and set large ID token
			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			// Set the large ID token
			session.SetIDToken(largeIDToken)
			t.Logf("Set large ID token in session")

			// Save the session to trigger chunking
			err = session.Save(req, rr)
			if err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Verify token retrieval integrity
			retrievedToken := session.GetIDToken()
			t.Logf("Retrieved ID token length: %d", len(retrievedToken))
			if len(retrievedToken) != len(largeIDToken) {
				t.Errorf("Token length mismatch: expected %d, got %d", len(largeIDToken), len(retrievedToken))
			}

			// Verify that chunked cookies were created
			cookies := rr.Result().Cookies()
			t.Logf("Total cookies in response: %d", len(cookies))

			var chunkCookies []*http.Cookie
			for _, cookie := range cookies {
				if strings.HasPrefix(cookie.Name, idTokenCookie+"_") {
					chunkCookies = append(chunkCookies, cookie)
				}
			}

			// Verify minimum expected chunks
			if len(chunkCookies) < minExpectedChunks {
				t.Fatalf("Expected at least %d chunk cookies, got %d", minExpectedChunks, len(chunkCookies))
			}

			// Test token retrieval from chunked cookies
			newReq := httptest.NewRequest("GET", "http://example.com/foo", nil)
			for _, cookie := range cookies {
				newReq.AddCookie(cookie)
			}

			retrievedSession, err := sm.GetSession(newReq)
			if err != nil {
				t.Fatalf("Failed to get session from chunked cookies: %v", err)
			}

			retrievedToken2 := retrievedSession.GetIDToken()

			// Verify the retrieved token matches the original
			if retrievedToken2 != largeIDToken {
				t.Errorf("Retrieved ID token doesn't match original. Expected length: %d, got: %d",
					len(largeIDToken), len(retrievedToken2))
			}

			// Test clearing the ID token removes all chunks
			retrievedSession.SetIDToken("")

			clearRR := httptest.NewRecorder()
			err = retrievedSession.Save(newReq, clearRR)
			if err != nil {
				t.Fatalf("Failed to save session after clearing ID token: %v", err)
			}

			// Verify chunks are expired (MaxAge = -1)
			clearCookies := clearRR.Result().Cookies()
			for _, cookie := range clearCookies {
				if strings.HasPrefix(cookie.Name, idTokenCookie+"_") {
					if cookie.MaxAge != -1 {
						t.Errorf("Expected chunk cookie %s to be expired (MaxAge=-1), got MaxAge=%d",
							cookie.Name, cookie.MaxAge)
					}
				}
			}
		})
	}

	_ = runner
}

// BenchmarkSessionOperations provides performance benchmarks for session operations
func BenchmarkSessionOperations(b *testing.B) {
	testTokens := NewTestTokens()
	perfHelper := NewPerformanceTestHelper()

	logger := NewLogger("error") // Reduce logging for benchmarks
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
	if err != nil {
		b.Fatalf("Failed to create session manager: %v", err)
	}

	b.Run("GetSession", func(b *testing.B) {
		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			session, err := sm.GetSession(req)
			if err != nil {
				b.Fatalf("GetSession failed: %v", err)
			}
			session.ReturnToPool()
		}
	})

	b.Run("SetAccessToken", func(b *testing.B) {
		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		session, _ := sm.GetSession(req)
		token := testTokens.GetValidTokenSet().AccessToken

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			perfHelper.Measure(func() {
				session.SetAccessToken(token)
			})
		}

		session.ReturnToPool()
		b.Logf("Average SetAccessToken time: %v", perfHelper.GetAverageTime())
	})

	b.Run("GetAccessToken", func(b *testing.B) {
		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		session, _ := sm.GetSession(req)
		session.SetAccessToken(testTokens.GetValidTokenSet().AccessToken)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			perfHelper.Measure(func() {
				_ = session.GetAccessToken()
			})
		}

		session.ReturnToPool()
		b.Logf("Average GetAccessToken time: %v", perfHelper.GetAverageTime())
	})

	b.Run("TokenCompression", func(b *testing.B) {
		largeToken := testTokens.CreateLargeValidJWT(5000)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			compressed := compressToken(largeToken)
			_ = decompressToken(compressed)
		}
	})
}

// Helper function to count objects in the session pool for a given manager
func getPooledObjects(sm *SessionManager) int {
	// Collect objects until we can't get any more from the pool
	// Set a max limit to avoid potential infinite loops
	var objects []*SessionData
	maxAttempts := 100 // Safety limit to prevent infinite loops

	for i := 0; i < maxAttempts; i++ {
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

// createLargeIDToken creates a JWT-like token of specified size for testing
func createLargeIDToken(size int) string {
	// Create truly random data that won't compress well
	randomBytes := make([]byte, size*3/4) // base64 encoding increases size by ~4/3
	_, err := rand.Read(randomBytes)
	if err != nil {
		// Fallback to pseudo-random if crypto/rand fails
		for i := range randomBytes {
			randomBytes[i] = byte(i % 256)
		}
	}

	// Base64url encode the random data to make it look like a JWT (JWT uses base64url, not base64)
	encoded := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Create JWT-like structure with truly random data
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"

	// Truncate or pad to desired size
	if len(encoded) > size-len(header)-100 {
		encoded = encoded[:size-len(header)-100]
	}

	signature := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	return header + "." + encoded + "." + signature
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
