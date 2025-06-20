package traefikoidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// TestTokens provides a comprehensive set of standardized test tokens
// for consistent testing across the entire codebase.
type TestTokens struct{}

// NewTestTokens creates a new TestTokens instance
func NewTestTokens() *TestTokens {
	return &TestTokens{}
}

// Valid JWT tokens for testing
const (
	// ValidAccessToken - A properly formatted JWT access token for testing
	ValidAccessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIiwidHlwIjoiSldUIn0.eyJhdWQiOiJ0ZXN0LWNsaWVudC1pZCIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSIsImV4cCI6MTc1MDI5NDYyOCwiaWF0IjoxNzUwMjkxMDI4LCJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJqdGkiOiJlNDcxN2RhZDBmZjAyOTNkIiwibmJmIjoxNzUwMjkxMDI4LCJub25jZSI6Im5vbmNlMTIzIiwic3ViIjoidGVzdC1zdWJqZWN0In0.bmwp-vk0B7Ir9UiUkzib8L7yJbebJ00o3U9QrB6gP2H9-RfqyCbN8M9Rkx7Rb8Vdh3YzqkBBoLS_G0i414rs2I9uABnTC4E6-63qkGdUrLB7p-XbjcRW2RoIBwXHk7lfumi8eX0uWzBsJ9CY0__UECVsex5XORfBb4Bcqj0LK4y-glxkpI51I7BPySfciWC_PkdaQ1Qe5pCAlxeNs2E9NMGXp-Ox6vAufUzoC2cws1LswGPPP6icQ-Zlzd5WMCIWhdIkN4yTxk8FMqsTC52k2zskRHNSSd4DDVETonfzawZNqDcMpnTyN53sCJ9UHiQTl9mCm61ttYW-W9Gc-ze4Xw"

	// ValidIDToken - A properly formatted JWT ID token for testing
	ValidIDToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIiwidHlwIjoiSldUIn0.eyJhdWQiOiJ0ZXN0LWNsaWVudC1pZCIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSIsImV4cCI6MTc1MDI5NDYyOCwiaWF0IjoxNzUwMjkxMDI4LCJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJqdGkiOiI2YzBjZTZmMTM4Y2EzMzc2IiwibmJmIjoxNzUwMjkxMDI4LCJub25jZSI6Im5vbmNlMTIzIiwic3ViIjoidGVzdC1zdWJqZWN0In0.RBQYejA9vP4lnh2EhFqWerePWaCyDTF0ZE1jlU2xm4g2wWVeaEHpv5SNg92_gwk633N9xx7ugS0UrlEu4qbT7wSb1HBDR00q_andyYnyFk4OoxPpD0AqHkVr-pjS-Z7UCGF3sLgQ4ECmU9695PIys3XvgUGMzEn_mK-PHcpY5AnbBGFsbj7epUld_sb6WfjjjwAa8kKfKObPvaIpuJ4TlxI1Uf0wYOoIA0zh5ipeAn-i8Ud-GErxis1Hp8UQK7IRolXpToiXnFcnf3vI3eCS7Yu3oPl7LRxTxKMCI9h0MCwu25ZNsOg2C9ohyebpU0jbURX9Q74GNOaphv-Lz9rCRA"

	// ValidRefreshToken - A properly formatted refresh token for testing
	ValidRefreshToken = "valid-refresh-token-12345"

	// MinimalValidJWT - The shortest valid JWT for testing
	MinimalValidJWT = "h.p.s"

	// ValidRefreshTokenGoogle - A Google-style refresh token for testing
	ValidRefreshTokenGoogle = "google_refresh_token_12345"
)

// Invalid tokens for testing validation
const (
	// InvalidTokenNoDots - Token with no dots (invalid JWT format)
	InvalidTokenNoDots = "notajwttoken"

	// InvalidTokenOneDot - Token with one dot (invalid JWT format)
	InvalidTokenOneDot = "header.payload"

	// InvalidTokenThreeDots - Token with three dots (invalid JWT format)
	InvalidTokenThreeDots = "header.payload.signature.extra"

	// EmptyToken - Empty token
	EmptyToken = ""

	// CorruptedBase64Token - Token with invalid base64 data for chunking tests
	CorruptedBase64Token = "corrupted_base64_!@#$"
)

// CreateLargeValidJWT creates a JWT of approximately the specified size
// This replaces the ad-hoc createLargeValidJWT function in tests
func (tt *TestTokens) CreateLargeValidJWT(targetSize int) string {
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	signature := "signature_" + tt.generateRandomString(32)

	// Calculate required payload size
	usedSize := len(header) + len(signature) + 2 // account for dots
	payloadSize := targetSize - usedSize
	if payloadSize < 50 {
		payloadSize = 50
	}

	// Create a payload with realistic JWT claims
	claims := map[string]interface{}{
		"sub": "user123",
		"iss": "https://example.com",
		"aud": "client123",
		"exp": 9999999999,
		"iat": 1000000000,
	}

	dataSize := payloadSize - 100 // Account for other claims and base64 encoding
	if dataSize < 10 {
		dataSize = 10 // Minimum data size
	}

	claims["data"] = tt.generateRandomString(dataSize)

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

// CreateLargeRefreshToken creates a refresh token of approximately the specified size
func (tt *TestTokens) CreateLargeRefreshToken(targetSize int) string {
	baseToken := "refresh_token_"
	padding := tt.generateRandomString(targetSize - len(baseToken))
	return baseToken + padding
}

// CreateExpiredJWT creates an expired JWT token for testing
func (tt *TestTokens) CreateExpiredJWT() string {
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"

	// Create claims with expired timestamp
	claims := map[string]interface{}{
		"sub": "user123",
		"iss": "https://example.com",
		"aud": "client123",
		"exp": time.Now().Unix() - 3600, // Expired 1 hour ago
		"iat": time.Now().Unix() - 7200, // Issued 2 hours ago
	}

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := "expired_signature"

	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

// CreateUniqueValidJWT creates a unique valid JWT for concurrent testing
func (tt *TestTokens) CreateUniqueValidJWT(id string) string {
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"

	claims := map[string]interface{}{
		"sub": "user_" + id,
		"iss": "https://example.com",
		"aud": "client123",
		"exp": 9999999999,
		"iat": 1000000000,
		"jti": id,
	}

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := "sig_" + id

	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

// CreateIncompressibleToken creates a token that cannot be compressed effectively
// This is useful for testing chunking scenarios where compression doesn't help
func (tt *TestTokens) CreateIncompressibleToken(targetSize int) string {
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	signature := "incompressible_signature_" + tt.generateRandomString(32)

	// Calculate required payload size
	usedSize := len(header) + len(signature) + 2 // account for dots
	payloadSize := max(targetSize-usedSize, 100)

	// Generate multiple random fields to prevent compression
	randomFields := make(map[string]interface{})
	randomFields["sub"] = "user123"
	randomFields["iss"] = "https://example.com"
	randomFields["aud"] = "client123"
	randomFields["exp"] = 9999999999
	randomFields["iat"] = 1000000000

	// Add many random fields with random data to prevent compression
	remainingSize := payloadSize - 200 // Account for base64 encoding and other fields
	fieldCount := remainingSize / 100  // ~100 bytes per field
	if fieldCount < 1 {
		fieldCount = 1
	}

	for i := 0; i < fieldCount; i++ {
		// Generate truly random data for each field
		randomBytes := make([]byte, 50)
		rand.Read(randomBytes)
		fieldName := fmt.Sprintf("random_field_%d_%s", i, tt.generateRandomString(8))
		randomFields[fieldName] = base64.StdEncoding.EncodeToString(randomBytes)
	}

	claimsJSON, _ := json.Marshal(randomFields)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	token := fmt.Sprintf("%s.%s.%s", header, payload, signature)

	// If still too small, pad with more random data
	if len(token) < targetSize {
		padding := targetSize - len(token)
		extraRandomBytes := make([]byte, padding/2)
		rand.Read(extraRandomBytes)
		randomFields["padding"] = base64.StdEncoding.EncodeToString(extraRandomBytes)
		claimsJSON, _ = json.Marshal(randomFields)
		payload = base64.RawURLEncoding.EncodeToString(claimsJSON)
		token = fmt.Sprintf("%s.%s.%s", header, payload, signature)
	}

	return token
}

// GetValidTokenSet returns a complete set of valid tokens for testing
func (tt *TestTokens) GetValidTokenSet() TokenSet {
	return TokenSet{
		AccessToken:  ValidAccessToken,
		IDToken:      ValidIDToken,
		RefreshToken: ValidRefreshToken,
	}
}

// GetGoogleTokenSet returns tokens that simulate Google OIDC provider responses
func (tt *TestTokens) GetGoogleTokenSet() TokenSet {
	return TokenSet{
		AccessToken:  ValidAccessToken,
		IDToken:      ValidIDToken,
		RefreshToken: ValidRefreshTokenGoogle,
	}
}

// GetLargeTokenSet returns a set of large tokens for chunking tests
func (tt *TestTokens) GetLargeTokenSet() TokenSet {
	return TokenSet{
		AccessToken:  tt.CreateLargeValidJWT(5000),
		IDToken:      tt.CreateLargeValidJWT(2000),
		RefreshToken: tt.CreateLargeRefreshToken(3000),
	}
}

// GetInvalidTokens returns various invalid tokens for validation testing
func (tt *TestTokens) GetInvalidTokens() InvalidTokenSet {
	return InvalidTokenSet{
		NoDots:    InvalidTokenNoDots,
		OneDot:    InvalidTokenOneDot,
		ThreeDots: InvalidTokenThreeDots,
		Empty:     EmptyToken,
		Corrupted: CorruptedBase64Token,
	}
}

// generateRandomString creates a random string of the specified length
func (tt *TestTokens) generateRandomString(length int) string {
	// FIXED: Handle negative or zero lengths safely
	if length <= 0 {
		return ""
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		randomByte := make([]byte, 1)
		rand.Read(randomByte)
		b[i] = charset[int(randomByte[0])%len(charset)]
	}
	return string(b)
}

// TokenSet represents a complete set of tokens for testing
type TokenSet struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
}

// InvalidTokenSet represents various invalid tokens for validation testing
type InvalidTokenSet struct {
	NoDots    string // Token with 0 dots
	OneDot    string // Token with 1 dot
	ThreeDots string // Token with 3 dots
	Empty     string // Empty token
	Corrupted string // Corrupted/invalid characters
}

// TestScenarios provides predefined test scenarios
type TestScenarios struct {
	tokens *TestTokens
}

// NewTestScenarios creates a new TestScenarios instance
func NewTestScenarios() *TestScenarios {
	return &TestScenarios{
		tokens: NewTestTokens(),
	}
}

// NormalFlow returns tokens for normal authentication flow testing
func (ts *TestScenarios) NormalFlow() TokenSet {
	return ts.tokens.GetValidTokenSet()
}

// GoogleFlow returns tokens simulating Google OIDC provider
func (ts *TestScenarios) GoogleFlow() TokenSet {
	return ts.tokens.GetGoogleTokenSet()
}

// ChunkingRequired returns large tokens that require chunking
func (ts *TestScenarios) ChunkingRequired() TokenSet {
	return ts.tokens.GetLargeTokenSet()
}

// CorruptionTest returns tokens and corruption scenarios for testing
func (ts *TestScenarios) CorruptionTest() CorruptionTestSet {
	return CorruptionTestSet{
		ValidTokens:    ts.tokens.GetValidTokenSet(),
		InvalidTokens:  ts.tokens.GetInvalidTokens(),
		LargeTokens:    ts.tokens.GetLargeTokenSet(),
		CorruptedToken: CorruptedBase64Token,
	}
}

// ConcurrentTest returns unique tokens for concurrent testing
func (ts *TestScenarios) ConcurrentTest(count int) []TokenSet {
	sets := make([]TokenSet, count)
	for i := 0; i < count; i++ {
		sets[i] = TokenSet{
			AccessToken:  ts.tokens.CreateUniqueValidJWT(fmt.Sprintf("concurrent_%d", i)),
			IDToken:      ts.tokens.CreateUniqueValidJWT(fmt.Sprintf("id_%d", i)),
			RefreshToken: fmt.Sprintf("refresh_concurrent_%d", i),
		}
	}
	return sets
}

// CorruptionTestSet represents tokens and scenarios for corruption testing
type CorruptionTestSet struct {
	ValidTokens    TokenSet
	InvalidTokens  InvalidTokenSet
	LargeTokens    TokenSet
	CorruptedToken string
}

// TokenValidationTestCases returns test cases for token validation
func (tt *TestTokens) TokenValidationTestCases() []ValidationTestCase {
	return []ValidationTestCase{
		{
			Name:            "Empty token",
			Token:           EmptyToken,
			ExpectStored:    true,  // Empty tokens are allowed for clearing
			ExpectRetrieved: false, // But return as empty
		},
		{
			Name:            "Single dot",
			Token:           InvalidTokenOneDot,
			ExpectStored:    false, // Invalid JWT format
			ExpectRetrieved: false,
		},
		{
			Name:            "No dots",
			Token:           InvalidTokenNoDots,
			ExpectStored:    false, // Invalid JWT format
			ExpectRetrieved: false,
		},
		{
			Name:            "Too many dots",
			Token:           InvalidTokenThreeDots,
			ExpectStored:    false, // Invalid JWT format
			ExpectRetrieved: false,
		},
		{
			Name:            "Valid minimal JWT",
			Token:           MinimalValidJWT,
			ExpectStored:    true,
			ExpectRetrieved: true,
		},
		{
			Name:            "Valid standard JWT",
			Token:           ValidAccessToken,
			ExpectStored:    true,
			ExpectRetrieved: true,
		},
	}
}

// ValidationTestCase represents a single token validation test case
type ValidationTestCase struct {
	Name            string
	Token           string
	ExpectStored    bool
	ExpectRetrieved bool
}

// Helper functions for common test patterns

// AssertValidTokenStorage verifies that a valid token can be stored and retrieved
func AssertValidTokenStorage(t TestingInterface, session *SessionData, token string) {
	session.SetAccessToken(token)
	retrieved := session.GetAccessToken()
	if retrieved != token {
		t.Errorf("Token storage failed: expected %q, got %q", token, retrieved)
	}
}

// AssertInvalidTokenRejection verifies that an invalid token is rejected
func AssertInvalidTokenRejection(t TestingInterface, session *SessionData, token string) {
	original := session.GetAccessToken()
	session.SetAccessToken(token)
	after := session.GetAccessToken()
	if after != original {
		t.Errorf("Invalid token was not rejected: expected %q, got %q", original, after)
	}
}

// TestingInterface provides the minimal interface needed for testing
type TestingInterface interface {
	Errorf(format string, args ...interface{})
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
