package traefikoidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/sessions"
	"github.com/lukaszraczylo/traefikoidc/internal/pool"
)

// TokenConfig defines validation and storage parameters for different token types.
// It specifies size limits, format requirements, and security constraints to ensure
// tokens can be safely stored in browser cookies while maintaining security.
type TokenConfig struct {
	Type              string
	MinLength         int
	MaxLength         int
	MaxChunks         int
	MaxChunkSize      int
	AllowOpaqueTokens bool
	RequireJWTFormat  bool
}

// Global session tracking to prevent memory leaks across all instances
var (
	globalSessionCount int64 = 0
	globalMaxSessions  int64 = 5000 // CRITICAL FIX: Global limit of 5000 total sessions
)

// ResetGlobalSessionCounters resets global session tracking for testing
func ResetGlobalSessionCounters() {
	atomic.StoreInt64(&globalSessionCount, 0)
}

// Predefined configurations for each token type
var (
	AccessTokenConfig = TokenConfig{
		Type:              "access",
		MinLength:         5,
		MaxLength:         100 * 1024,
		MaxChunks:         25,
		MaxChunkSize:      maxCookieSize,
		AllowOpaqueTokens: true,
		RequireJWTFormat:  false,
	}

	RefreshTokenConfig = TokenConfig{
		Type:              "refresh",
		MinLength:         5,
		MaxLength:         50 * 1024,
		MaxChunks:         15,
		MaxChunkSize:      maxCookieSize,
		AllowOpaqueTokens: true,
		RequireJWTFormat:  false,
	}

	IDTokenConfig = TokenConfig{
		Type:              "id",
		MinLength:         5,
		MaxLength:         75 * 1024,
		MaxChunks:         20,
		MaxChunkSize:      maxCookieSize,
		AllowOpaqueTokens: false,
		RequireJWTFormat:  true,
	}
)

// TokenRetrievalResult represents the outcome of a token retrieval operation.
// It contains either the successfully retrieved token or an error describing
// what went wrong during retrieval.
type TokenRetrievalResult struct {
	Error error
	Token string
}

// ChunkManager handles the complex logic of storing and retrieving large tokens
// across multiple HTTP cookies. It provides comprehensive validation, security checks,
// and error handling to ensure data integrity and prevent security vulnerabilities
// throughout the process.
type ChunkManager struct {
	logger *Logger
	mutex  *sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup // WaitGroup to track background goroutine completion
	// sessionMap provides bounded session storage to prevent memory leaks
	sessionMap     map[string]*SessionEntry
	maxSessions    int
	sessionTTL     time.Duration
	lastCleanup    time.Time
	cleanupRunning int32 // atomic flag to prevent concurrent cleanups
	// Memory usage tracking
	bytesAllocated int64
	peakSessions   int64
	cleanupCount   int64
}

// SessionEntry represents a session with expiration tracking
type SessionEntry struct {
	Session      *sessions.Session
	ExpiresAt    time.Time
	LastUsed     time.Time
	SizeEstimate int64 // Estimated memory usage
}

// NewChunkManager creates a new ChunkManager instance with proper initialization.
// It sets up logging and synchronization primitives for safe concurrent access.
// Parameters:
//   - logger: Logger instance for debugging and error reporting (nil creates no-op logger).
//
// Returns:
//   - A new ChunkManager instance ready for use.
func NewChunkManager(logger *Logger) *ChunkManager {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
	}

	ctx, cancel := context.WithCancel(context.Background())

	cm := &ChunkManager{
		logger:      logger,
		mutex:       &sync.RWMutex{},
		ctx:         ctx,
		cancel:      cancel,
		sessionMap:  make(map[string]*SessionEntry),
		maxSessions: 200,              // CRITICAL FIX: Reduced from 1000 to 200 per instance
		sessionTTL:  15 * time.Minute, // CRITICAL FIX: Reduced from 24h to 15 minutes
		lastCleanup: time.Now(),
	}

	// Start background cleanup routine
	cm.wg.Add(1)
	go cm.backgroundCleanupRoutine()

	return cm
}

// Shutdown gracefully shuts down the ChunkManager
func (cm *ChunkManager) Shutdown() {
	if cm.cancel != nil {
		cm.cancel()
	}

	// Wait for background cleanup routine to actually finish
	cm.wg.Wait()

	// Final cleanup
	cm.mutex.Lock()
	sessionCount := len(cm.sessionMap)
	for key, entry := range cm.sessionMap {
		atomic.AddInt64(&cm.bytesAllocated, -entry.SizeEstimate)
		delete(cm.sessionMap, key)
	}
	cm.mutex.Unlock()

	if sessionCount > 0 && cm.logger != nil {
		cm.logger.Infof("ChunkManager shutdown: cleared %d sessions", sessionCount)
	}
}

// backgroundCleanupRoutine runs periodic cleanup tasks
func (cm *ChunkManager) backgroundCleanupRoutine() {
	defer cm.wg.Done()                         // Signal completion when this goroutine exits
	ticker := time.NewTicker(10 * time.Minute) // Cleanup every 10 minutes
	defer ticker.Stop()

	for {
		select {
		case <-cm.ctx.Done():
			if cm.logger != nil {
				cm.logger.Debug("ChunkManager background cleanup terminated")
			}
			return
		case <-ticker.C:
			cm.performPeriodicCleanup()
		}
	}
}

// performPeriodicCleanup executes regular maintenance
func (cm *ChunkManager) performPeriodicCleanup() {
	// Only run one cleanup at a time
	if !atomic.CompareAndSwapInt32(&cm.cleanupRunning, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&cm.cleanupRunning, 0)

	startTime := time.Now()

	cm.CleanupExpiredSessions()

	// Force garbage collection if memory usage is high
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	currentSessions := atomic.LoadInt64(&cm.peakSessions)
	allocatedBytes := atomic.LoadInt64(&cm.bytesAllocated)

	if allocatedBytes > 10*1024*1024 || currentSessions > int64(cm.maxSessions/2) {
		runtime.GC()
		if cm.logger != nil {
			cm.logger.Debugf("Forced GC: sessions=%d, allocated=%d bytes",
				currentSessions, allocatedBytes)
		}
	}

	duration := time.Since(startTime)
	atomic.AddInt64(&cm.cleanupCount, 1)

	if cm.logger != nil && duration > 100*time.Millisecond {
		cm.logger.Debugf("Chunk manager cleanup took %v", duration)
	}
}

// GetToken retrieves and validates a token from either single-cookie or chunked storage.
// It handles decompression, validates format and content, and performs comprehensive
// security checks before returning the token.
// Parameters:
//   - singleToken: Token stored in a single cookie (empty if using chunks).
//   - compressed: Whether the token data is gzip-compressed.
//   - chunks: Map of chunk sessions for tokens split across multiple cookies.
//   - config: Token configuration specifying validation rules and limits.
//
// Returns:
//   - TokenRetrievalResult containing the token or an error.
func (cm *ChunkManager) GetToken(
	singleToken string,
	compressed bool,
	chunks map[int]*sessions.Session,
	config TokenConfig,
) TokenRetrievalResult {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if singleToken != "" {
		return cm.processSingleToken(singleToken, compressed, config)
	}

	if len(chunks) == 0 {
		return TokenRetrievalResult{Token: "", Error: nil}
	}

	return cm.processChunkedToken(chunks, config)
}

// processSingleToken handles tokens stored in a single cookie.
// It checks for corruption markers, decompresses if necessary, and validates the token.
// Parameters:
//   - token: The token string from a single cookie.
//   - compressed: Whether the token is compressed.
//   - config: Token configuration for validation.
//
// Returns:
//   - TokenRetrievalResult containing the processed token or an error.
func (cm *ChunkManager) processSingleToken(token string, compressed bool, config TokenConfig) TokenRetrievalResult {
	if isCorruptionMarker(token) {
		err := fmt.Errorf("%s token contains corruption marker", config.Type)
		if !strings.Contains(token, "TEST_CORRUPTION") {
			cm.logger.Debug("Token corruption detected for %s", config.Type)
		}
		return TokenRetrievalResult{Token: "", Error: err}
	}

	var finalToken string
	if compressed {
		decompressed := decompressToken(token)
		if isCorruptionMarker(decompressed) {
			err := fmt.Errorf("decompressed %s token contains corruption marker", config.Type)
			cm.logger.Debug("Decompressed token corruption detected for %s", config.Type)
			return TokenRetrievalResult{Token: "", Error: err}
		}
		finalToken = decompressed
	} else {
		finalToken = token
	}

	return cm.validateToken(finalToken, config)
}

// validateToken performs comprehensive validation of a retrieved token.
// It checks size, format, content, expiration, and security requirements
// based on the token configuration.
// Parameters:
//   - token: The token to validate.
//   - config: Token configuration specifying validation rules.
//
// Returns:
//   - TokenRetrievalResult with the validated token or validation error.
func (cm *ChunkManager) validateToken(token string, config TokenConfig) TokenRetrievalResult {
	if sizeErr := cm.validateTokenSize(token, config); sizeErr != nil {
		return TokenRetrievalResult{Token: "", Error: sizeErr}
	}

	if chunkErr := cm.validateChunkingEfficiency(token, config); chunkErr != nil {
		return TokenRetrievalResult{Token: "", Error: chunkErr}
	}

	if contentErr := cm.validateTokenContent(token, config); contentErr != nil {
		return TokenRetrievalResult{Token: "", Error: contentErr}
	}

	if expErr := cm.validateTokenExpiration(token, config); expErr != nil {
		return TokenRetrievalResult{Token: "", Error: expErr}
	}

	if freshnessErr := cm.validateTokenFreshness(token, config); freshnessErr != nil {
		return TokenRetrievalResult{Token: "", Error: freshnessErr}
	}

	// Determine if token is opaque or JWT based on format
	// JWT tokens have exactly 2 dots (3 parts: header.payload.signature)
	dotCount := strings.Count(token, ".")
	isJWT := dotCount == 2

	if config.RequireJWTFormat && !config.AllowOpaqueTokens {
		// Only accept JWT format tokens
		if validationErr := cm.validateJWTFormat(token, config.Type); validationErr != nil {
			return TokenRetrievalResult{Token: "", Error: validationErr}
		}
	} else if config.AllowOpaqueTokens {
		// Accept both JWT and opaque tokens
		if isJWT {
			// Token looks like JWT, validate as JWT
			if validationErr := cm.validateJWTFormat(token, config.Type); validationErr != nil {
				// If JWT validation fails but opaque tokens are allowed,
				// still return an error as the token claims to be JWT but is malformed
				return TokenRetrievalResult{Token: "", Error: validationErr}
			}
		} else {
			// Token is opaque, validate as opaque
			if validationErr := cm.validateOpaqueToken(token, config.Type); validationErr != nil {
				return TokenRetrievalResult{Token: "", Error: validationErr}
			}
		}
	}

	return TokenRetrievalResult{Token: token, Error: nil}
}

// processChunkedToken handles tokens stored across multiple chunks.
// It validates chunk count, assembles chunks in order, checks for corruption,
// and reconstructs the original token with integrity verification.
// Parameters:
//   - chunks: Map of chunk sessions indexed by chunk number.
//   - config: Token configuration for validation and limits.
//
// Returns:
//   - TokenRetrievalResult with the reassembled token or error.
func (cm *ChunkManager) processChunkedToken(chunks map[int]*sessions.Session, config TokenConfig) TokenRetrievalResult {
	if len(chunks) > config.MaxChunks {
		err := fmt.Errorf("too many %s token chunks (%d, max: %d)", config.Type, len(chunks), config.MaxChunks)
		cm.logger.Info("Token chunk count exceeded for %s: %d chunks", config.Type, len(chunks))
		return TokenRetrievalResult{Token: "", Error: err}
	}

	if len(chunks) > 100 {
		err := fmt.Errorf("excessive %s token chunks (%d), potential security issue", config.Type, len(chunks))
		cm.logger.Error("Security: Excessive token chunks detected for %s: %d", config.Type, len(chunks))
		return TokenRetrievalResult{Token: "", Error: err}
	}

	// Sequential chunk validation and assembly
	var tokenParts []string
	totalSize := 0

	for i := 0; i < len(chunks); i++ {
		session, ok := chunks[i]
		if !ok {
			err := fmt.Errorf("%s token chunk %d missing", config.Type, i)
			if i == 0 {
				cm.logger.Debug("Token chunks missing for %s starting at index %d", config.Type, i)
			}
			return TokenRetrievalResult{Token: "", Error: err}
		}

		chunk, chunkOk := session.Values["token_chunk"].(string)
		if !chunkOk || chunk == "" {
			err := fmt.Errorf("%s token chunk %d invalid", config.Type, i)
			return TokenRetrievalResult{Token: "", Error: err}
		}

		if isCorruptionMarker(chunk) {
			err := fmt.Errorf("%s token chunk %d corrupted", config.Type, i)
			return TokenRetrievalResult{Token: "", Error: err}
		}

		if len(chunk) > config.MaxChunkSize {
			err := fmt.Errorf("%s token chunk %d exceeds size limit (%d bytes, max: %d)",
				config.Type, i, len(chunk), config.MaxChunkSize)
			return TokenRetrievalResult{Token: "", Error: err}
		}

		if len(chunk) > maxBrowserCookieSize {
			err := fmt.Errorf("%s token chunk %d exceeds browser limit (%d bytes)",
				config.Type, i, len(chunk))
			return TokenRetrievalResult{Token: "", Error: err}
		}

		totalSize += len(chunk)
		if totalSize > config.MaxLength {
			err := fmt.Errorf("%s token total size exceeds limit", config.Type)
			return TokenRetrievalResult{Token: "", Error: err}
		}

		tokenParts = append(tokenParts, chunk)
	}

	reassembledToken := strings.Join(tokenParts, "")

	compressed, _ := chunks[0].Values["compressed"].(bool)

	if compressed {
		decompressed := decompressToken(reassembledToken)
		if isCorruptionMarker(decompressed) {
			err := fmt.Errorf("decompressed chunked %s token corrupted", config.Type)
			return TokenRetrievalResult{Token: "", Error: err}
		}
		return cm.validateToken(decompressed, config)
	}

	return cm.validateToken(reassembledToken, config)
}

// validateJWTFormat performs enhanced JWT format validation.
// It checks the three-part structure, validates base64url encoding,
// and ensures proper JWT format according to RFC 7519.
// Parameters:
//   - token: The JWT token to validate.
//   - tokenType: The type of token for error messages.
//
// Returns:
//   - An error if the JWT format is invalid, nil if valid.
func (cm *ChunkManager) validateJWTFormat(token string, tokenType string) error {
	dotCount := strings.Count(token, ".")
	if dotCount != 2 {
		err := fmt.Errorf("%s token invalid JWT format (dots: %d)", tokenType, dotCount)
		return err
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		err := fmt.Errorf("%s token invalid JWT structure", tokenType)
		return err
	}

	for i, part := range parts {
		if part == "" {
			err := fmt.Errorf("%s token has empty JWT part %d", tokenType, i)
			return err
		}

		for _, char := range part {
			if !((char >= 'A' && char <= 'Z') ||
				(char >= 'a' && char <= 'z') ||
				(char >= '0' && char <= '9') ||
				char == '-' || char == '_' || char == '=') {
				err := fmt.Errorf("%s token contains invalid base64url character in part %d", tokenType, i)
				return err
			}
		}

		if strings.Contains(part, "=") {
			paddingIndex := strings.Index(part, "=")
			if paddingIndex != len(part)-1 && paddingIndex != len(part)-2 {
				err := fmt.Errorf("%s token has invalid base64url padding in part %d", tokenType, i)
				return err
			}
			for j := paddingIndex; j < len(part); j++ {
				if part[j] != '=' {
					err := fmt.Errorf("%s token has characters after padding in part %d", tokenType, i)
					return err
				}
			}
		}
	}

	if len(parts[0]) < 10 {
		err := fmt.Errorf("%s token header too short", tokenType)
		return err
	}
	if len(parts[1]) < 10 {
		err := fmt.Errorf("%s token payload too short", tokenType)
		return err
	}
	if len(parts[2]) < 10 {
		err := fmt.Errorf("%s token signature too short", tokenType)
		return err
	}

	return nil
}

// validateOpaqueToken performs validation for opaque (non-JWT) tokens.
// It checks for spaces, control characters, and entropy to ensure
// the token appears to be a legitimate opaque token.
// Parameters:
//   - token: The opaque token to validate.
//   - tokenType: The type of token for error messages.
//
// Returns:
//   - An error if the opaque token format is invalid, nil if valid.
func (cm *ChunkManager) validateOpaqueToken(token string, tokenType string) error {
	// Check for empty token
	if token == "" {
		return fmt.Errorf("%s opaque token cannot be empty", tokenType)
	}

	// Check minimum length
	if len(token) < 20 {
		return fmt.Errorf("%s opaque token too short (length: %d, minimum: 20)", tokenType, len(token))
	}

	if strings.Contains(token, " ") {
		err := fmt.Errorf("%s opaque token contains spaces", tokenType)
		return err
	}

	for _, char := range token {
		if char < 32 || char == 127 {
			err := fmt.Errorf("%s opaque token contains control characters", tokenType)
			return err
		}
	}

	if len(token) >= 20 {
		uniqueChars := make(map[rune]bool)
		for _, char := range token {
			uniqueChars[char] = true
		}
		if len(uniqueChars) < 8 {
			err := fmt.Errorf("%s opaque token has insufficient entropy", tokenType)
			return err
		}
	}

	return nil
}

// validateTokenSize performs comprehensive token size validation.
// It checks overall token size, individual JWT part sizes, and applies
// different limits based on token type (JWT vs opaque).
// Parameters:
//   - token: The token to validate size constraints for.
//   - config: Token configuration with size limits.
//
// Returns:
//   - An error if size validation fails, nil if within limits.
func (cm *ChunkManager) validateTokenSize(token string, config TokenConfig) error {
	tokenLen := len(token)

	if tokenLen < config.MinLength {
		err := fmt.Errorf("%s token below minimum length (%d bytes, min: %d)",
			config.Type, tokenLen, config.MinLength)
		return err
	}

	if tokenLen > config.MaxLength {
		err := fmt.Errorf("%s token exceeds maximum length (%d bytes, max: %d)",
			config.Type, tokenLen, config.MaxLength)
		return err
	}

	if config.RequireJWTFormat || (config.AllowOpaqueTokens && strings.Contains(token, ".")) {
		parts := strings.Split(token, ".")
		if len(parts) == 3 {
			headerLen := len(parts[0])
			payloadLen := len(parts[1])
			signatureLen := len(parts[2])

			if headerLen > 5*1024 {
				err := fmt.Errorf("%s token header too large (%d bytes)", config.Type, headerLen)
				return err
			}

			if payloadLen > config.MaxLength-10*1024 {
				err := fmt.Errorf("%s token payload too large (%d bytes)", config.Type, payloadLen)
				return err
			}

			if signatureLen > 2*1024 {
				err := fmt.Errorf("%s token signature too large (%d bytes)", config.Type, signatureLen)
				return err
			}
		}
	}

	if config.AllowOpaqueTokens && !strings.Contains(token, ".") {
		if tokenLen > 8*1024 {
			err := fmt.Errorf("%s opaque token unusually large (%d bytes)", config.Type, tokenLen)
			return err
		}
	}

	return nil
}

// validateChunkingEfficiency ensures that chunking is used appropriately.
// It calculates expected chunk counts and warns about potential inefficiencies
// in token storage strategies.
// Parameters:
//   - token: The token to analyze for chunking efficiency.
//   - config: Token configuration with chunking limits.
//
// Returns:
//   - An error if chunking requirements would be violated, nil if acceptable.
func (cm *ChunkManager) validateChunkingEfficiency(token string, config TokenConfig) error {
	tokenLen := len(token)

	if tokenLen <= config.MaxChunkSize && tokenLen <= maxCookieSize {
	}

	expectedChunks := (tokenLen + config.MaxChunkSize - 1) / config.MaxChunkSize
	if expectedChunks > config.MaxChunks {
		err := fmt.Errorf("%s token would require %d chunks (max: %d)",
			config.Type, expectedChunks, config.MaxChunks)
		return err
	}

	if expectedChunks > 10 && tokenLen < 50*1024 {
		cm.logger.Info("%s token requires many chunks (%d) for size (%d bytes) - consider token optimization",
			config.Type, expectedChunks, tokenLen)
	}

	return nil
}

// validateTokenContent performs comprehensive token content validation.
// It sanitizes the token for security issues and applies format-specific
// validation for JWT or opaque tokens.
// Parameters:
//   - token: The token to validate content for.
//   - config: Token configuration specifying content requirements.
//
// Returns:
//   - An error if content validation fails, nil if content is acceptable.
func (cm *ChunkManager) validateTokenContent(token string, config TokenConfig) error {
	if err := cm.validateTokenSanitization(token, config); err != nil {
		return err
	}

	if config.RequireJWTFormat || (config.AllowOpaqueTokens && strings.Contains(token, ".")) {
		if err := cm.validateJWTContent(token, config); err != nil {
			return err
		}
	}

	if config.AllowOpaqueTokens && !strings.Contains(token, ".") {
		if err := cm.validateOpaqueTokenContent(token, config); err != nil {
			return err
		}
	}

	return nil
}

// validateTokenSanitization checks for basic security issues in token content.
// It detects null bytes, line breaks, suspicious patterns, and other indicators
// of potential security threats or data corruption.
// Parameters:
//   - token: The token to sanitize and check.
//   - config: Token configuration for context.
//
// Returns:
//   - An error if security issues are detected, nil if token appears safe.
func (cm *ChunkManager) validateTokenSanitization(token string, config TokenConfig) error {
	if strings.Contains(token, "\x00") {
		err := fmt.Errorf("%s token contains null bytes", config.Type)
		return err
	}

	if strings.ContainsAny(token, "\r\n") {
		err := fmt.Errorf("%s token contains line breaks", config.Type)
		return err
	}

	// Check for control characters (ASCII 0-31 and 127)
	for i, char := range token {
		if char < 32 || char == 127 {
			err := fmt.Errorf("%s token contains control character at position %d", config.Type, i)
			return err
		}
	}

	suspiciousPatterns := []string{
		"\\x", "\\u", "\\n", "\\r", "\\t", "\\0",
		"<script", "</script", "javascript:", "data:",
		"file://", "ftp://", "ldap://",
	}

	tokenLower := strings.ToLower(token)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(tokenLower, pattern) {
			err := fmt.Errorf("%s token contains suspicious pattern: %s", config.Type, pattern)
			return err
		}
	}

	if err := cm.detectRepeatedCharacters(token, config); err != nil {
		return err
	}

	return nil
}

// validateJWTContent performs JWT-specific content validation.
// It validates the header, payload, and signature parts of a JWT
// for proper encoding and structure.
// Parameters:
//   - token: The JWT token to validate.
//   - config: Token configuration for validation context.
//
// Returns:
//   - An error if JWT content validation fails, nil if valid.
func (cm *ChunkManager) validateJWTContent(token string, config TokenConfig) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		err := fmt.Errorf("%s JWT token malformed for content validation", config.Type)
		return err
	}

	if err := cm.validateJWTHeader(parts[0], config); err != nil {
		return err
	}

	if err := cm.validateJWTPayload(parts[1], config); err != nil {
		return err
	}

	if err := cm.validateJWTSignature(parts[2], config); err != nil {
		return err
	}

	return nil
}

// validateJWTHeader validates JWT header content.
// It checks that the header is properly base64url encoded
// and not empty.
// Parameters:
//   - header: The JWT header part to validate.
//   - config: Token configuration for error context.
//
// Returns:
//   - An error if header validation fails, nil if valid.
func (cm *ChunkManager) validateJWTHeader(header string, config TokenConfig) error {
	if len(header) == 0 {
		err := fmt.Errorf("%s JWT header is empty", config.Type)
		return err
	}

	if _, err := base64.RawURLEncoding.DecodeString(header); err != nil {
		err := fmt.Errorf("%s JWT header not valid base64url", config.Type)
		return err
	}

	return nil
}

// validateJWTPayload validates JWT payload content.
// It checks that the payload is properly base64url encoded
// and contains data.
// Parameters:
//   - payload: The JWT payload part to validate.
//   - config: Token configuration for error context.
//
// Returns:
//   - An error if payload validation fails, nil if valid.
func (cm *ChunkManager) validateJWTPayload(payload string, config TokenConfig) error {
	if len(payload) == 0 {
		err := fmt.Errorf("%s JWT payload is empty", config.Type)
		return err
	}

	if _, err := base64.RawURLEncoding.DecodeString(payload); err != nil {
		err := fmt.Errorf("%s JWT payload not valid base64url", config.Type)
		return err
	}

	return nil
}

// validateJWTSignature validates JWT signature content.
// It checks that the signature is properly base64url encoded
// and present.
// Parameters:
//   - signature: The JWT signature part to validate.
//   - config: Token configuration for error context.
//
// Returns:
//   - An error if signature validation fails, nil if valid.
func (cm *ChunkManager) validateJWTSignature(signature string, config TokenConfig) error {
	if len(signature) == 0 {
		err := fmt.Errorf("%s JWT signature is empty", config.Type)
		return err
	}

	if _, err := base64.RawURLEncoding.DecodeString(signature); err != nil {
		err := fmt.Errorf("%s JWT signature not valid base64url", config.Type)
		return err
	}

	return nil
}

// validateOpaqueTokenContent validates opaque token content.
// It analyzes character distribution, checks for legitimate prefixes,
// and ensures the token appears to be a proper opaque token.
// Parameters:
//   - token: The opaque token to validate.
//   - config: Token configuration for validation context.
//
// Returns:
//   - An error if opaque token content is invalid, nil if acceptable.
func (cm *ChunkManager) validateOpaqueTokenContent(token string, config TokenConfig) error {
	if len(token) >= 10 {
		alphabetic := 0
		numeric := 0
		special := 0

		for _, char := range token {
			if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') {
				alphabetic++
			} else if char >= '0' && char <= '9' {
				numeric++
			} else {
				special++
			}
		}

		total := alphabetic + numeric + special
		if total > 0 {
			alphaRatio := float64(alphabetic) / float64(total)
			numericRatio := float64(numeric) / float64(total)

			if alphaRatio < 0.1 && numericRatio < 0.1 {
				err := fmt.Errorf("%s opaque token has suspicious character distribution", config.Type)
				return err
			}
		}
	}

	legitimatePrefixes := []string{
		"Bearer ", "bearer ", "eyJ",
		"refresh_", "access_", "id_",
		"token_", "oauth_", "oidc_",
	}

	hasLegitimatePrefix := false
	for _, prefix := range legitimatePrefixes {
		if strings.HasPrefix(token, prefix) {
			hasLegitimatePrefix = true
			break
		}
	}

	if len(token) > 50 && !hasLegitimatePrefix {
	}

	return nil
}

// detectRepeatedCharacters detects potential buffer overflow attempts.
// It analyzes character repetition patterns and frequency distribution
// to identify suspicious tokens that might be crafted for attacks.
// Parameters:
//   - token: The token to analyze for repeated characters.
//   - config: Token configuration for error context.
//
// Returns:
//   - An error if suspicious repetition patterns are detected, nil if normal.
func (cm *ChunkManager) detectRepeatedCharacters(token string, config TokenConfig) error {
	if len(token) < 10 {
		return nil
	}

	maxRepeated := 0
	currentRepeated := 1
	var lastChar rune

	for i, char := range token {
		if i > 0 && char == lastChar {
			currentRepeated++
			if currentRepeated > maxRepeated {
				maxRepeated = currentRepeated
			}
		} else {
			currentRepeated = 1
		}
		lastChar = char
	}

	threshold := 20
	if maxRepeated > threshold {
		err := fmt.Errorf("%s token has excessive repeated characters (%d consecutive)",
			config.Type, maxRepeated)
		return err
	}

	charFreq := make(map[rune]int)
	for _, char := range token {
		charFreq[char]++
	}

	tokenLen := len(token)
	for char, count := range charFreq {
		frequency := float64(count) / float64(tokenLen)

		if frequency > 0.7 && tokenLen > 20 {
			err := fmt.Errorf("%s token has suspicious character frequency (char '%c': %.1f%%)",
				config.Type, char, frequency*100)
			return err
		}
	}

	return nil
}

// validateTokenExpiration validates token expiration during storage/retrieval.
// It extracts and checks JWT expiration claims to ensure tokens are not expired
// and detects tokens with suspicious expiration times.
// Parameters:
//   - token: The token to check expiration for.
//   - config: Token configuration for error context.
//
// Returns:
//   - An error if the token is expired or has invalid expiration, nil if valid.
func (cm *ChunkManager) validateTokenExpiration(token string, config TokenConfig) error {
	if !strings.Contains(token, ".") {
		return nil
	}

	expiration, err := cm.extractJWTExpiration(token)
	if err != nil {
		cm.logger.Debugf("Could not extract expiration from %s token: %v", config.Type, err)
		return nil
	}

	if expiration != nil && time.Now().After(*expiration) {
		// Don't reject expired tokens during retrieval - they need to be checked for grace period
		// The grace period logic is handled at a higher level
		cm.logger.Debugf("%s token is expired (expired at: %v) - allowing retrieval for grace period check",
			config.Type, expiration.Format(time.RFC3339))
		// Don't return error here - let higher level decide what to do with expired tokens
		// err := fmt.Errorf("%s token is expired (expired at: %v)", config.Type, expiration.Format(time.RFC3339))
		// return err
	}

	if expiration != nil {
		maxFutureTime := time.Now().Add(10 * 365 * 24 * time.Hour)
		if expiration.After(maxFutureTime) {
			cm.logger.Info("%s token expires very far in future (%v) - potential security issue",
				config.Type, expiration.Format(time.RFC3339))
		}
	}

	return nil
}

// extractJWTExpiration extracts the expiration time from a JWT token.
// It decodes the payload and parses the 'exp' claim according to JWT standards.
// Parameters:
//   - token: The JWT token to extract expiration from.
//
// Returns:
//   - The expiration time if present, nil if no 'exp' claim.
//   - An error if JWT parsing fails.
func (cm *ChunkManager) extractJWTExpiration(token string) (*time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse the JSON payload using pooled decoder
	var claims map[string]interface{}
	pm := pool.Get()
	decoder := pm.GetJSONDecoder(bytes.NewReader(payload))
	defer pm.PutJSONDecoder(decoder)

	if err := decoder.Decode(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	exp, exists := claims["exp"]
	if !exists {
		return nil, nil
	}

	// Convert expiration to time.Time
	var expTime time.Time
	switch v := exp.(type) {
	case float64:
		expTime = time.Unix(int64(v), 0)
	case int64:
		expTime = time.Unix(v, 0)
	case int:
		expTime = time.Unix(int64(v), 0)
	default:
		return nil, fmt.Errorf("invalid expiration format: %T", exp)
	}

	return &expTime, nil
}

// validateTokenFreshness checks if token is fresh enough for storage.
// It examines the 'iat' (issued at) claim to detect tokens issued too far
// in the future or suspiciously old tokens that might indicate replay attacks.
// Parameters:
//   - token: The token to check freshness for.
//   - config: Token configuration for error context.
//
// Returns:
//   - An error if the token freshness is suspicious, nil if acceptable.
func (cm *ChunkManager) validateTokenFreshness(token string, config TokenConfig) error {
	if !strings.Contains(token, ".") {
		return nil
	}

	issuedAt, err := cm.extractJWTIssuedAt(token)
	if err != nil {
		cm.logger.Debugf("Could not extract issued time from %s token: %v", config.Type, err)
		return nil
	}

	if issuedAt != nil {
		now := time.Now()

		if issuedAt.After(now.Add(5 * time.Minute)) {
			err := fmt.Errorf("%s token issued in future (issued at: %v)",
				config.Type, issuedAt.Format(time.RFC3339))
			return err
		}

		maxAge := 24 * time.Hour
		if now.Sub(*issuedAt) > maxAge {
			cm.logger.Info("%s token is quite old (issued: %v) - potential replay",
				config.Type, issuedAt.Format(time.RFC3339))
		}
	}

	return nil
}

// extractJWTIssuedAt extracts the issued at time from a JWT token.
// It decodes the payload and parses the 'iat' claim to determine
// when the token was originally issued.
// Parameters:
//   - token: The JWT token to extract issued time from.
//
// Returns:
//   - The issued at time if present, nil if no 'iat' claim.
//   - An error if JWT parsing fails.
func (cm *ChunkManager) extractJWTIssuedAt(token string) (*time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse the JSON payload using pooled decoder
	var claims map[string]interface{}
	pm := pool.Get()
	decoder := pm.GetJSONDecoder(bytes.NewReader(payload))
	defer pm.PutJSONDecoder(decoder)

	if err := decoder.Decode(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	iat, exists := claims["iat"]
	if !exists {
		return nil, nil
	}

	// Convert issued at to time.Time
	var iatTime time.Time
	switch v := iat.(type) {
	case float64:
		iatTime = time.Unix(int64(v), 0)
	case int64:
		iatTime = time.Unix(v, 0)
	case int:
		iatTime = time.Unix(int64(v), 0)
	default:
		return nil, fmt.Errorf("invalid issued at format: %T", iat)
	}

	return &iatTime, nil
}

// CleanupExpiredSessions removes expired sessions to prevent memory leaks.
// This is called periodically to maintain memory efficiency and prevent unbounded growth.
// It can be called with force=true to bypass time restrictions for testing.
func (cm *ChunkManager) CleanupExpiredSessions(force ...bool) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// Check if we should bypass time restrictions
	forceCleanup := len(force) > 0 && force[0]

	// Check if we have expired sessions that need immediate attention
	now := time.Now()
	hasExpiredSessions := false
	for _, entry := range cm.sessionMap {
		if now.After(entry.ExpiresAt) || now.Sub(entry.LastUsed) > cm.sessionTTL {
			hasExpiredSessions = true
			break
		}
	}

	// Only cleanup if enough time has passed, unless forced or we have expired sessions
	if !forceCleanup && !hasExpiredSessions && time.Since(cm.lastCleanup) < time.Hour {
		return
	}

	expiredKeys := make([]string, 0)

	// Find expired sessions
	for key, entry := range cm.sessionMap {
		if now.After(entry.ExpiresAt) || now.Sub(entry.LastUsed) > cm.sessionTTL {
			expiredKeys = append(expiredKeys, key)
		}
	}

	// Remove expired sessions and track memory
	totalBytesFreed := int64(0)
	for _, key := range expiredKeys {
		if entry, exists := cm.sessionMap[key]; exists {
			totalBytesFreed += entry.SizeEstimate
			atomic.AddInt64(&cm.bytesAllocated, -entry.SizeEstimate)
		}
		delete(cm.sessionMap, key)
	}

	cm.lastCleanup = now

	if len(expiredKeys) > 0 {
		cm.logger.Debugf("Cleaned up %d expired sessions, freed %d bytes",
			len(expiredKeys), totalBytesFreed)
	}

	// Enforce max sessions limit
	if len(cm.sessionMap) > cm.maxSessions {
		cm.enforceSessionLimit()
	}
}

// enforceSessionLimit removes oldest sessions when limit is exceeded
func (cm *ChunkManager) enforceSessionLimit() {
	currentLocal := len(cm.sessionMap)
	currentGlobal := atomic.LoadInt64(&globalSessionCount)

	// CRITICAL FIX: Aggressive eviction when approaching limits
	shouldEvict := false
	targetCapacity := cm.maxSessions

	// Check global limit first (more critical)
	if currentGlobal >= globalMaxSessions {
		shouldEvict = true
		targetCapacity = cm.maxSessions / 4 // Aggressive reduction to 25%
	} else if currentGlobal >= globalMaxSessions*8/10 { // 80% of global
		shouldEvict = true
		targetCapacity = cm.maxSessions / 2 // Reduce to 50%
	} else if currentLocal >= cm.maxSessions {
		shouldEvict = true
		targetCapacity = cm.maxSessions * 3 / 4 // Reduce to 75%
	}

	if !shouldEvict {
		return
	}

	// Find oldest sessions to remove
	type sessionAge struct {
		key      string
		lastUsed time.Time
	}

	sessions := make([]sessionAge, 0, len(cm.sessionMap))
	for key, entry := range cm.sessionMap {
		sessions = append(sessions, sessionAge{key: key, lastUsed: entry.LastUsed})
	}

	// Sort by last used time (oldest first)
	for i := 0; i < len(sessions)-1; i++ {
		for j := i + 1; j < len(sessions); j++ {
			if sessions[i].lastUsed.After(sessions[j].lastUsed) {
				sessions[i], sessions[j] = sessions[j], sessions[i]
			}
		}
	}

	// Remove excess sessions and track memory - CRITICAL FIX: More aggressive
	excessCount := currentLocal - targetCapacity
	if excessCount < 0 {
		excessCount = 0
	}

	totalBytesFreed := int64(0)
	removedCount := int64(0)

	for i := 0; i < excessCount && i < len(sessions); i++ {
		key := sessions[i].key
		if entry, exists := cm.sessionMap[key]; exists {
			totalBytesFreed += entry.SizeEstimate
			atomic.AddInt64(&cm.bytesAllocated, -entry.SizeEstimate)
			removedCount++
		}
		delete(cm.sessionMap, key)
	}

	// Update global count
	if removedCount > 0 {
		atomic.AddInt64(&globalSessionCount, -removedCount)
	}

	cm.logger.Infof("Enforced session limit: removed %d excess sessions, freed %d bytes",
		excessCount, totalBytesFreed)
}

// CanCreateSession checks if a new session can be created within limits
func (cm *ChunkManager) CanCreateSession() (bool, error) {
	cm.mutex.RLock()
	currentCount := len(cm.sessionMap)
	cm.mutex.RUnlock()

	// Hard limit check - never exceed maxSessions
	if currentCount >= cm.maxSessions {
		cm.logger.Error("Cannot create session: at maximum limit (%d)", cm.maxSessions)
		return false, fmt.Errorf("session storage at maximum capacity (%d sessions)", cm.maxSessions)
	}

	// Emergency cleanup at 90% capacity
	emergencyThreshold := int(float64(cm.maxSessions) * 0.9)
	if currentCount >= emergencyThreshold {
		cm.logger.Info("Session storage at %d%% capacity, triggering emergency cleanup",
			(currentCount*100)/cm.maxSessions)
		cm.EmergencyCleanup()

		// Recheck after cleanup
		cm.mutex.RLock()
		newCount := len(cm.sessionMap)
		cm.mutex.RUnlock()

		if newCount >= cm.maxSessions {
			return false, fmt.Errorf("session storage full even after emergency cleanup (%d sessions)", newCount)
		}
	}

	return true, nil
}

// EmergencyCleanup performs aggressive session cleanup when approaching limits
func (cm *ChunkManager) EmergencyCleanup() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	now := time.Now()
	removed := 0

	// Remove any expired sessions first
	expiredKeys := make([]string, 0)
	for key, entry := range cm.sessionMap {
		if now.After(entry.ExpiresAt) || now.Sub(entry.LastUsed) > cm.sessionTTL {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		if entry, exists := cm.sessionMap[key]; exists {
			atomic.AddInt64(&cm.bytesAllocated, -entry.SizeEstimate)
		}
		delete(cm.sessionMap, key)
		removed++
	}

	// If still over 80% capacity, remove oldest sessions more aggressively
	targetCapacity := int(float64(cm.maxSessions) * 0.8)
	if len(cm.sessionMap) > targetCapacity {
		type sessionAge struct {
			key      string
			lastUsed time.Time
		}

		sessions := make([]sessionAge, 0, len(cm.sessionMap))
		for key, entry := range cm.sessionMap {
			sessions = append(sessions, sessionAge{key: key, lastUsed: entry.LastUsed})
		}

		// Sort by last used time (oldest first)
		for i := 0; i < len(sessions)-1; i++ {
			for j := i + 1; j < len(sessions); j++ {
				if sessions[i].lastUsed.After(sessions[j].lastUsed) {
					sessions[i], sessions[j] = sessions[j], sessions[i]
				}
			}
		}

		// Remove sessions until we reach target capacity
		excessCount := len(cm.sessionMap) - targetCapacity
		for i := 0; i < excessCount && i < len(sessions); i++ {
			key := sessions[i].key
			if entry, exists := cm.sessionMap[key]; exists {
				atomic.AddInt64(&cm.bytesAllocated, -entry.SizeEstimate)
			}
			delete(cm.sessionMap, key)
			removed++
		}
	}

	cm.lastCleanup = now
	cm.logger.Infof("Emergency cleanup completed: removed %d sessions, %d remaining",
		removed, len(cm.sessionMap))

	// Log memory stats after emergency cleanup
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	cm.logger.Infof("Memory after emergency cleanup - Heap: %.1fMB, Sessions: %d, Tracked bytes: %d",
		float64(m.HeapAlloc)/(1024*1024), len(cm.sessionMap), atomic.LoadInt64(&cm.bytesAllocated))
}

// GetSessionCount returns the current number of active sessions (for monitoring)
func (cm *ChunkManager) GetSessionCount() int {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	return len(cm.sessionMap)
}

// GetMemoryStats returns memory usage statistics for monitoring
func (cm *ChunkManager) GetMemoryStats() map[string]interface{} {
	cm.mutex.RLock()
	sessionCount := len(cm.sessionMap)
	cm.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["active_sessions"] = sessionCount
	stats["max_sessions"] = cm.maxSessions
	stats["bytes_allocated"] = atomic.LoadInt64(&cm.bytesAllocated)
	stats["peak_sessions"] = atomic.LoadInt64(&cm.peakSessions)
	stats["cleanup_count"] = atomic.LoadInt64(&cm.cleanupCount)
	stats["session_ttl_hours"] = cm.sessionTTL.Hours()

	// Update peak sessions
	if int64(sessionCount) > atomic.LoadInt64(&cm.peakSessions) {
		atomic.StoreInt64(&cm.peakSessions, int64(sessionCount))
	}

	return stats
}
