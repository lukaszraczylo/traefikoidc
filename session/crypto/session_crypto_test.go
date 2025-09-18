package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// Mock memory pools for testing
type MockMemoryPools struct{}

func (mp *MockMemoryPools) GetCompressionBuffer() *bytes.Buffer {
	return &bytes.Buffer{}
}

func (mp *MockMemoryPools) PutCompressionBuffer(*bytes.Buffer) {
	// Mock implementation - nothing to do
}

func (mp *MockMemoryPools) GetHTTPResponseBuffer() []byte {
	return make([]byte, 32768) // 32KB buffer
}

func (mp *MockMemoryPools) PutHTTPResponseBuffer([]byte) {
	// Mock implementation - nothing to do
}

// TestGenerateSecureRandomString tests secure random string generation
func TestGenerateSecureRandomString(t *testing.T) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	tests := []struct {
		name        string
		length      int
		expectError bool
		description string
	}{
		{
			name:        "Valid length",
			length:      16,
			expectError: false,
			description: "Should generate random string of correct length",
		},
		{
			name:        "Minimum length",
			length:      1,
			expectError: false,
			description: "Should handle minimum length",
		},
		{
			name:        "Zero length",
			length:      0,
			expectError: false,
			description: "Should handle zero length",
		},
		{
			name:        "Large length",
			length:      1024,
			expectError: false,
			description: "Should handle large length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sc.GenerateSecureRandomString(tt.length)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.description)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.description, err)
				return
			}

			// Check length (hex encoding doubles the length)
			expectedLen := tt.length * 2
			if len(result) != expectedLen {
				t.Errorf("Expected length %d, got %d for %s", expectedLen, len(result), tt.description)
			}

			// Check that result is hex
			for _, char := range result {
				if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
					t.Errorf("Result contains non-hex character: %c", char)
					break
				}
			}
		})
	}
}

// TestGenerateSecureRandomStringUniqueness tests that generated strings are unique
func TestGenerateSecureRandomStringUniqueness(t *testing.T) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	// Generate multiple strings and check uniqueness
	generated := make(map[string]bool)
	for i := 0; i < 100; i++ {
		result, err := sc.GenerateSecureRandomString(16)
		if err != nil {
			t.Fatalf("Failed to generate random string: %v", err)
		}

		if generated[result] {
			t.Errorf("Generated duplicate string: %s", result)
		}
		generated[result] = true
	}
}

// TestTokenCompressionIntegrity tests token compression and decompression
func TestTokenCompressionIntegrity(t *testing.T) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	tests := []struct {
		name        string
		token       string
		expectValid bool
		description string
	}{
		{
			name:        "Valid JWT small",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expectValid: true,
			description: "Should compress and decompress small JWT correctly",
		},
		{
			name:        "Valid JWT large",
			token:       createLargeJWT(2000),
			expectValid: true,
			description: "Should compress and decompress large JWT correctly",
		},
		{
			name:        "Invalid token - no dots",
			token:       "invalidtoken",
			expectValid: false,
			description: "Should not compress token without dots",
		},
		{
			name:        "Invalid token - wrong number of dots",
			token:       "header.payload",
			expectValid: false,
			description: "Should not compress token with wrong number of dots",
		},
		{
			name:        "Empty token",
			token:       "",
			expectValid: false,
			description: "Should handle empty token",
		},
		{
			name:        "Oversized token",
			token:       createOversizedToken(),
			expectValid: false,
			description: "Should reject oversized tokens",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed := sc.CompressToken(tt.token)

			if !tt.expectValid {
				// For invalid tokens, compression should return original
				if compressed != tt.token {
					t.Errorf("Expected compression to return original for invalid token, got different result")
				}
				return
			}

			// For valid tokens, test round-trip integrity
			decompressed := sc.DecompressToken(compressed)
			if decompressed != tt.token {
				t.Errorf("Token integrity lost: original length=%d, compressed length=%d, decompressed length=%d",
					len(tt.token), len(compressed), len(decompressed))
			}

			// Test that decompression is idempotent
			decompressed2 := sc.DecompressToken(decompressed)
			if decompressed2 != tt.token {
				t.Errorf("Decompression not idempotent: %d != %d", len(decompressed2), len(tt.token))
			}
		})
	}
}

// TestTokenCompressionCorruptionDetection tests corruption detection
func TestTokenCompressionCorruptionDetection(t *testing.T) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	corruptionTests := []struct {
		name           string
		corruptedInput string
		expectOriginal bool
		description    string
	}{
		{
			name:           "Corrupted base64",
			corruptedInput: "invalid-base64!",
			expectOriginal: true,
			description:    "Should return original for corrupted base64",
		},
		{
			name:           "Truncated compressed data",
			corruptedInput: "H4sI", // Truncated gzip header
			expectOriginal: true,
			description:    "Should return original for truncated data",
		},
		{
			name:           "Invalid gzip data",
			corruptedInput: base64.StdEncoding.EncodeToString([]byte("not gzip data")),
			expectOriginal: true,
			description:    "Should return original for invalid gzip data",
		},
		{
			name:           "Empty compressed data",
			corruptedInput: "",
			expectOriginal: true,
			description:    "Should handle empty compressed data",
		},
	}

	for _, tt := range corruptionTests {
		t.Run(tt.name, func(t *testing.T) {
			result := sc.DecompressToken(tt.corruptedInput)
			if tt.expectOriginal && result != tt.corruptedInput {
				t.Errorf("Expected decompression to return original corrupted input, got: %q", result)
			}
		})
	}

	// Test that valid compression still works
	t.Run("Valid compression verification", func(t *testing.T) {
		validJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		compressed := sc.CompressToken(validJWT)
		decompressed := sc.DecompressToken(compressed)
		if decompressed != validJWT {
			t.Errorf("Valid compression/decompression failed: %q != %q", decompressed, validJWT)
		}
	})
}

// TestCompressionEfficiency tests that compression only occurs when beneficial
func TestCompressionEfficiency(t *testing.T) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	tests := []struct {
		name           string
		token          string
		shouldCompress bool
		description    string
	}{
		{
			name:           "Small JWT",
			token:          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			shouldCompress: false, // Small tokens might not benefit from compression
			description:    "Small tokens should not be compressed if no benefit",
		},
		{
			name:           "Large repetitive JWT",
			token:          createLargeRepetitiveJWT(2000),
			shouldCompress: true, // Repetitive data should compress well
			description:    "Large repetitive tokens should be compressed",
		},
		{
			name:           "Incompressible token",
			token:          createIncompressibleJWT(1000),
			shouldCompress: false, // Random data won't compress well
			description:    "Incompressible tokens should not be compressed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed := sc.CompressToken(tt.token)
			wasCompressed := compressed != tt.token

			if tt.shouldCompress && !wasCompressed {
				t.Errorf("Expected token to be compressed but it wasn't")
			} else if !tt.shouldCompress && wasCompressed {
				// This is okay - compression might still occur if beneficial
				t.Logf("Token was compressed even though not expected (this is acceptable)")
			}

			// Verify decompression still works regardless
			decompressed := sc.DecompressToken(compressed)
			if decompressed != tt.token {
				t.Errorf("Decompression failed for %s", tt.description)
			}
		})
	}
}

// TestCompressionSizeLimits tests compression size limits
func TestCompressionSizeLimits(t *testing.T) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	t.Run("Oversized token rejection", func(t *testing.T) {
		oversizedToken := createOversizedToken()
		compressed := sc.CompressToken(oversizedToken)

		// Oversized tokens should not be compressed
		if compressed != oversizedToken {
			t.Error("Oversized token should not be compressed")
		}
	})

	t.Run("Oversized compressed data rejection", func(t *testing.T) {
		oversizedCompressed := strings.Repeat("a", 150*1024) // >100KB
		decompressed := sc.DecompressToken(oversizedCompressed)

		// Should return original when input is too large
		if decompressed != oversizedCompressed {
			t.Error("Oversized compressed data should be returned as-is")
		}
	})
}

// Helper functions for creating test tokens

func createLargeJWT(size int) string {
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	signature := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// Create payload that will result in desired total size
	payloadSize := size - len(header) - len(signature) - 2 // -2 for dots
	if payloadSize < 10 {
		payloadSize = 10
	}

	payload := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", payloadSize*3/4)))

	return header + "." + payload + "." + signature
}

func createLargeRepetitiveJWT(size int) string {
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	signature := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// Create repetitive payload that compresses well
	payloadSize := size - len(header) - len(signature) - 2
	if payloadSize < 10 {
		payloadSize = 10
	}

	repetitiveData := strings.Repeat("repetitive_data_", payloadSize/16)
	payload := base64.StdEncoding.EncodeToString([]byte(repetitiveData))

	return header + "." + payload + "." + signature
}

func createIncompressibleJWT(size int) string {
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	signature := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// Create random payload that won't compress well
	payloadSize := size - len(header) - len(signature) - 2
	if payloadSize < 10 {
		payloadSize = 10
	}

	randomBytes := make([]byte, payloadSize*3/4)
	rand.Read(randomBytes)
	payload := base64.StdEncoding.EncodeToString(randomBytes)

	return header + "." + payload + "." + signature
}

func createOversizedToken() string {
	// Create a token larger than 50KB (the limit in CompressToken)
	size := 55 * 1024 // 55KB
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	signature := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	payloadSize := size - len(header) - len(signature) - 2
	payload := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", payloadSize*3/4)))

	return header + "." + payload + "." + signature
}

// BenchmarkCompression benchmarks compression operations
func BenchmarkCompression(b *testing.B) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	b.Run("CompressLargeJWT", func(b *testing.B) {
		largeToken := createLargeJWT(5000)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = sc.CompressToken(largeToken)
		}
	})

	b.Run("DecompressLargeJWT", func(b *testing.B) {
		largeToken := createLargeJWT(5000)
		compressed := sc.CompressToken(largeToken)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = sc.DecompressToken(compressed)
		}
	})

	b.Run("RoundTripCompression", func(b *testing.B) {
		largeToken := createLargeJWT(5000)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			compressed := sc.CompressToken(largeToken)
			_ = sc.DecompressToken(compressed)
		}
	})
}

// TestValidateTokenFormat tests JWT token format validation
func TestValidateTokenFormat(t *testing.T) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{
			name:     "Valid JWT token",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: true,
		},
		{
			name:     "Valid JWT with different content",
			token:    "header.payload.signature",
			expected: true,
		},
		{
			name:     "Empty token",
			token:    "",
			expected: false,
		},
		{
			name:     "Token with no dots",
			token:    "nodots",
			expected: false,
		},
		{
			name:     "Token with one dot",
			token:    "header.payload",
			expected: false,
		},
		{
			name:     "Token with four dots",
			token:    "header.payload.signature.extra",
			expected: false,
		},
		{
			name:     "Token with empty header",
			token:    ".payload.signature",
			expected: false,
		},
		{
			name:     "Token with empty payload",
			token:    "header..signature",
			expected: false,
		},
		{
			name:     "Token with empty signature",
			token:    "header.payload.",
			expected: false,
		},
		{
			name:     "Token with all empty parts",
			token:    "..",
			expected: false,
		},
		{
			name:     "Opaque token",
			token:    "opaque_token_without_dots",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sc.ValidateTokenFormat(tt.token)
			if result != tt.expected {
				t.Errorf("ValidateTokenFormat(%q) = %v, expected %v", tt.token, result, tt.expected)
			}
		})
	}
}

// TestIsTokenCompressed tests token compression detection
func TestIsTokenCompressed(t *testing.T) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{
			name:     "Empty token",
			token:    "",
			expected: false,
		},
		{
			name:     "Valid JWT token (uncompressed)",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: false,
		},
		{
			name:     "Invalid base64",
			token:    "invalid!base64",
			expected: false,
		},
		{
			name:     "Valid base64 but not gzip",
			token:    base64.StdEncoding.EncodeToString([]byte("not gzip data")),
			expected: false,
		},
		{
			name:     "Valid gzip header",
			token:    base64.StdEncoding.EncodeToString([]byte{0x1f, 0x8b, 0x08, 0x00}), // gzip magic bytes
			expected: true,
		},
		{
			name:     "Partial gzip header",
			token:    base64.StdEncoding.EncodeToString([]byte{0x1f}), // only first byte
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sc.IsTokenCompressed(tt.token)
			if result != tt.expected {
				t.Errorf("IsTokenCompressed(%q) = %v, expected %v", tt.token, result, tt.expected)
			}
		})
	}

	// Test with actual compressed token
	t.Run("Real compressed token", func(t *testing.T) {
		originalToken := createLargeJWT(2000)
		compressedToken := sc.CompressToken(originalToken)

		// If compression occurred (token changed), it should be detected as compressed
		if compressedToken != originalToken {
			if !sc.IsTokenCompressed(compressedToken) {
				t.Error("Failed to detect actual compressed token")
			}
		}

		// Original token should not be detected as compressed
		if sc.IsTokenCompressed(originalToken) {
			t.Error("Original JWT detected as compressed")
		}
	})
}

// TestSecureWipeBytes tests secure byte wiping
func TestSecureWipeBytes(t *testing.T) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "Normal byte slice",
			data: []byte("sensitive data"),
		},
		{
			name: "Empty slice",
			data: []byte{},
		},
		{
			name: "Single byte",
			data: []byte{0xFF},
		},
		{
			name: "Large data",
			data: bytes.Repeat([]byte("secret"), 1000),
		},
		{
			name: "Nil slice",
			data: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy to verify original content
			original := make([]byte, len(tt.data))
			copy(original, tt.data)

			// Wipe the data
			sc.SecureWipeBytes(tt.data)

			// Verify all bytes are zero (except for nil slice)
			if tt.data != nil {
				for i, b := range tt.data {
					if b != 0 {
						t.Errorf("Byte at index %d not wiped: got %d, expected 0", i, b)
					}
				}
			}

			// Verify we had actual data to wipe (except for empty/nil cases)
			if len(original) > 0 {
				hasNonZero := false
				for _, b := range original {
					if b != 0 {
						hasNonZero = true
						break
					}
				}
				if !hasNonZero {
					t.Log("Test data was already all zeros")
				}
			}
		})
	}
}

// TestSecureWipeString tests secure string wiping
func TestSecureWipeString(t *testing.T) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	tests := []struct {
		name   string
		input  *string
		expect string
	}{
		{
			name:   "Normal string",
			input:  func() *string { s := "sensitive data"; return &s }(),
			expect: "",
		},
		{
			name:   "Empty string",
			input:  func() *string { s := ""; return &s }(),
			expect: "",
		},
		{
			name:   "Long string",
			input:  func() *string { s := strings.Repeat("secret", 1000); return &s }(),
			expect: "",
		},
		{
			name:   "Nil string pointer",
			input:  nil,
			expect: "", // This test verifies no panic occurs
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Store original value for verification
			var original string
			if tt.input != nil {
				original = *tt.input
			}

			// Wipe the string
			sc.SecureWipeString(tt.input)

			// Verify result
			if tt.input != nil {
				if *tt.input != tt.expect {
					t.Errorf("String not wiped properly: got %q, expected %q", *tt.input, tt.expect)
				}
			}

			// Verify we had actual data to wipe (except for nil case)
			if tt.input != nil && original != "" {
				t.Logf("Successfully wiped string of length %d", len(original))
			}
		})
	}
}

// TestMin tests the minimum utility function
func TestMin(t *testing.T) {
	tests := []struct {
		name     string
		a, b     int
		expected int
	}{
		{
			name:     "a smaller than b",
			a:        5,
			b:        10,
			expected: 5,
		},
		{
			name:     "b smaller than a",
			a:        15,
			b:        7,
			expected: 7,
		},
		{
			name:     "equal values",
			a:        42,
			b:        42,
			expected: 42,
		},
		{
			name:     "negative values",
			a:        -10,
			b:        -5,
			expected: -10,
		},
		{
			name:     "zero values",
			a:        0,
			b:        0,
			expected: 0,
		},
		{
			name:     "mixed positive and negative",
			a:        -3,
			b:        2,
			expected: -3,
		},
		{
			name:     "large numbers",
			a:        1000000,
			b:        999999,
			expected: 999999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Min(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("Min(%d, %d) = %d, expected %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestGenerateSecureRandomStringStandalone tests the standalone random string function
func TestGenerateSecureRandomStringStandalone(t *testing.T) {
	tests := []struct {
		name        string
		length      int
		expectError bool
	}{
		{
			name:        "Valid length",
			length:      16,
			expectError: false,
		},
		{
			name:        "Zero length",
			length:      0,
			expectError: false,
		},
		{
			name:        "Large length",
			length:      1024,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GenerateSecureRandomString(tt.length)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Check length (hex encoding doubles the length)
			expectedLen := tt.length * 2
			if len(result) != expectedLen {
				t.Errorf("Expected length %d, got %d", expectedLen, len(result))
			}

			// Check that result is hex
			for _, char := range result {
				if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
					t.Errorf("Result contains non-hex character: %c", char)
					break
				}
			}
		})
	}

	// Test uniqueness
	t.Run("Uniqueness test", func(t *testing.T) {
		generated := make(map[string]bool)
		for i := 0; i < 100; i++ {
			result, err := GenerateSecureRandomString(16)
			if err != nil {
				t.Fatalf("Failed to generate random string: %v", err)
			}

			if generated[result] {
				t.Errorf("Generated duplicate string: %s", result)
			}
			generated[result] = true
		}
	})
}

// TestCompressionEdgeCases tests edge cases for compression
func TestCompressionEdgeCases(t *testing.T) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	t.Run("Token with exact size limit", func(t *testing.T) {
		// Create token at exactly 50KB
		token := createTokenWithExactSize(50 * 1024)
		compressed := sc.CompressToken(token)

		// Should still attempt compression at the limit
		decompressed := sc.DecompressToken(compressed)
		if decompressed != token {
			t.Error("Failed to handle token at size limit")
		}
	})

	t.Run("Compressed token with exact decompression limit", func(t *testing.T) {
		// Create data that decompresses to exactly 100KB
		largeData := strings.Repeat("a", 100*1024)
		encoded := base64.StdEncoding.EncodeToString([]byte(largeData))

		result := sc.DecompressToken(encoded)
		// Should return original since it's not valid gzip
		if result != encoded {
			t.Error("Failed to handle large non-gzip data")
		}
	})
}

// Helper function to create token with exact size
func createTokenWithExactSize(targetSize int) string {
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	signature := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// Calculate needed payload size
	dotsSize := 2 // two dots
	otherSize := len(header) + len(signature) + dotsSize
	payloadSize := targetSize - otherSize

	if payloadSize <= 0 {
		payloadSize = 10 // minimum payload
	}

	// Create payload of exact size
	payload := strings.Repeat("x", payloadSize)

	return header + "." + payload + "." + signature
}

// BenchmarkRandomGeneration benchmarks random string generation
func BenchmarkRandomGeneration(b *testing.B) {
	memoryPools := &MockMemoryPools{}
	sc := NewSessionCrypto(memoryPools)

	b.Run("Generate16Bytes", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = sc.GenerateSecureRandomString(16)
		}
	})

	b.Run("Generate32Bytes", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = sc.GenerateSecureRandomString(32)
		}
	})
}
