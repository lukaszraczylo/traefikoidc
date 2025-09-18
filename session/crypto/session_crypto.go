// Package crypto provides cryptographic operations for session management
package crypto

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// MemoryPools interface for memory management
type MemoryPools interface {
	GetCompressionBuffer() *bytes.Buffer
	PutCompressionBuffer(*bytes.Buffer)
	GetHTTPResponseBuffer() []byte
	PutHTTPResponseBuffer([]byte)
}

// SessionCrypto provides cryptographic operations for session data
type SessionCrypto struct {
	memoryPools MemoryPools
}

// NewSessionCrypto creates a new session crypto instance
func NewSessionCrypto(memoryPools MemoryPools) *SessionCrypto {
	return &SessionCrypto{
		memoryPools: memoryPools,
	}
}

// GenerateSecureRandomString creates a cryptographically secure random string.
// It generates random bytes using crypto/rand and encodes them as hexadecimal.
// This is used for session IDs and other security-sensitive random values.
func (sc *SessionCrypto) GenerateSecureRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// CompressToken compresses a JWT token using gzip compression if beneficial.
// It validates the token format, attempts compression, and verifies the compressed
// data can be decompressed correctly. Only compresses if it reduces size.
func (sc *SessionCrypto) CompressToken(token string) string {
	if token == "" {
		return token
	}

	// Validate JWT format (should have exactly 2 dots)
	dotCount := strings.Count(token, ".")
	if dotCount != 2 {
		return token
	}

	// Don't try to compress extremely large tokens
	if len(token) > 50*1024 {
		return token
	}

	b := sc.memoryPools.GetCompressionBuffer()
	defer sc.memoryPools.PutCompressionBuffer(b)

	gz := gzip.NewWriter(b)

	written, err := gz.Write([]byte(token))
	if err != nil || written != len(token) {
		return token
	}

	if err := gz.Close(); err != nil {
		return token
	}

	compressedBytes := b.Bytes()
	if len(compressedBytes) == 0 {
		return token
	}

	compressed := base64.StdEncoding.EncodeToString(compressedBytes)

	// Only use compression if it actually reduces size
	if len(compressed) >= len(token) {
		return token
	}

	// Verify compression integrity by attempting decompression
	decompressed := sc.decompressTokenInternal(compressed)
	if decompressed != token {
		return token
	}

	// Final validation of decompressed token
	if strings.Count(decompressed, ".") != 2 {
		return token
	}

	return compressed
}

// DecompressToken decompresses a previously compressed token string.
// It decodes the base64 data, validates gzip headers, and decompresses safely
// with size limits to prevent compression bombs.
func (sc *SessionCrypto) DecompressToken(compressed string) string {
	return sc.decompressTokenInternal(compressed)
}

// decompressTokenInternal is the internal decompression function.
// Separated internal function for integrity verification during compression.
// It performs the actual decompression logic with proper resource management.
func (sc *SessionCrypto) decompressTokenInternal(compressed string) string {
	if compressed == "" {
		return compressed
	}

	// Prevent decompression of extremely large inputs
	if len(compressed) > 100*1024 {
		return compressed
	}

	data, err := base64.StdEncoding.DecodeString(compressed)
	if err != nil {
		return compressed
	}

	if len(data) == 0 {
		return compressed
	}

	// Validate gzip header
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return compressed
	}

	readerBuf := sc.memoryPools.GetHTTPResponseBuffer()
	defer sc.memoryPools.PutHTTPResponseBuffer(readerBuf)

	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return compressed
	}

	defer func() {
		if closeErr := gz.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	// Limit decompressed size to prevent compression bombs
	limitedReader := io.LimitReader(gz, 500*1024)

	// Optimize for large buffer reuse
	if cap(readerBuf) >= 512*1024 {
		readerBuf = readerBuf[:cap(readerBuf)]
		n, err := limitedReader.Read(readerBuf)
		if err != nil && err != io.EOF {
			return compressed
		}
		decompressed := readerBuf[:n]
		return string(decompressed)
	}

	decompressed, err := io.ReadAll(limitedReader)
	if err != nil {
		return compressed
	}

	if len(decompressed) == 0 {
		return compressed
	}

	decompressedStr := string(decompressed)

	// Validate the decompressed token is a valid JWT
	if decompressedStr != "" && strings.Count(decompressedStr, ".") != 2 {
		return compressed
	}

	return decompressedStr
}

// ValidateTokenFormat validates that a token has the correct JWT format
func (sc *SessionCrypto) ValidateTokenFormat(token string) bool {
	if token == "" {
		return false
	}

	// JWT tokens should have exactly 3 parts separated by dots
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	// Each part should be non-empty
	for _, part := range parts {
		if part == "" {
			return false
		}
	}

	return true
}

// IsTokenCompressed checks if a token appears to be compressed
func (sc *SessionCrypto) IsTokenCompressed(token string) bool {
	if token == "" {
		return false
	}

	// JWT tokens have exactly 2 dots, compressed tokens don't
	if strings.Count(token, ".") == 2 {
		return false
	}

	// Try to decode as base64
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return false
	}

	// Check for gzip header
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return true
	}

	return false
}

// SecureWipeBytes securely wipes sensitive data from memory
func (sc *SessionCrypto) SecureWipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// SecureWipeString securely wipes sensitive string data
func (sc *SessionCrypto) SecureWipeString(s *string) {
	if s != nil {
		*s = ""
	}
}

// Utility functions that don't require instance state

// Min returns the minimum of two integers
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GenerateSecureRandomString creates a cryptographically secure random string without dependencies
func GenerateSecureRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
