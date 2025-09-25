// Package chunking provides session chunking functionality for large tokens
package chunking

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/sessions"
)

const (
	maxCookieSize = 1200
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

// SessionEntry represents a session with expiration tracking
type SessionEntry struct {
	Session   *sessions.Session
	ExpiresAt time.Time
	LastUsed  time.Time
}

// Logger interface for dependency injection
type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...interface{})
	Error(msg string)
	Errorf(format string, args ...interface{})
}

// ChunkManager handles the complex logic of storing and retrieving large tokens
// across multiple HTTP cookies. It provides comprehensive validation, security checks,
// and error handling to ensure data integrity and prevent security vulnerabilities
// throughout the process.
type ChunkManager struct {
	logger Logger
	mutex  *sync.RWMutex
	// sessionMap provides bounded session storage to prevent memory leaks
	sessionMap  map[string]*SessionEntry
	maxSessions int
	sessionTTL  time.Duration
	lastCleanup time.Time
}

// NewChunkManager creates a new ChunkManager instance with proper initialization.
// It sets up logging and synchronization primitives for safe concurrent access.
func NewChunkManager(logger Logger) *ChunkManager {
	if logger == nil {
		logger = NewNoOpLogger()
	}

	return &ChunkManager{
		logger:      logger,
		mutex:       &sync.RWMutex{},
		sessionMap:  make(map[string]*SessionEntry),
		maxSessions: 200,              // CRITICAL FIX: Reduced from 1000 to 200 per instance
		sessionTTL:  15 * time.Minute, // CRITICAL FIX: Reduced from 24h to 15 minutes
		lastCleanup: time.Now(),
	}
}

// GetToken retrieves a token from either a single cookie or multiple chunk cookies.
// It handles both compressed and uncompressed tokens and performs comprehensive
// validation throughout the retrieval process.
func (cm *ChunkManager) GetToken(
	mainSession *sessions.Session,
	chunks map[int]*sessions.Session,
	config TokenConfig,
	compressor TokenCompressor,
) TokenRetrievalResult {

	// Try to get token from main session first
	if mainSession != nil {
		if tokenValue, ok := mainSession.Values[config.Type+"_token"].(string); ok && tokenValue != "" {
			cm.logger.Debugf("Found %s token in main session", config.Type)

			// Check if token is compressed
			decompressed := compressor.DecompressToken(tokenValue)
			if decompressed != tokenValue {
				cm.logger.Debugf("Decompressed %s token", config.Type)
				return cm.processSingleToken(decompressed, true, config)
			}

			return cm.processSingleToken(tokenValue, false, config)
		}
	}

	// If not in main session, try chunks
	if len(chunks) == 0 {
		return TokenRetrievalResult{
			Error: nil,
			Token: "",
		}
	}

	cm.logger.Debugf("Found %d chunks for %s token, processing", len(chunks), config.Type)
	return cm.processChunkedToken(chunks, config, compressor)
}

// processSingleToken validates and processes a single token
func (cm *ChunkManager) processSingleToken(token string, compressed bool, config TokenConfig) TokenRetrievalResult {
	if compressed {
		cm.logger.Debugf("Processing compressed %s token (length: %d)", config.Type, len(token))
	} else {
		cm.logger.Debugf("Processing single %s token (length: %d)", config.Type, len(token))
	}

	return cm.validateToken(token, config)
}

// validateToken performs comprehensive validation on a token
func (cm *ChunkManager) validateToken(token string, config TokenConfig) TokenRetrievalResult {
	if token == "" {
		return TokenRetrievalResult{Error: nil, Token: ""}
	}

	validator := NewTokenValidator()

	// Basic validation
	if err := validator.ValidateTokenSize(token, config); err != nil {
		cm.logger.Errorf("Token size validation failed for %s: %v", config.Type, err)
		return TokenRetrievalResult{Error: err, Token: ""}
	}

	// Format validation
	if config.RequireJWTFormat {
		if err := validator.ValidateJWTFormat(token, config.Type); err != nil {
			cm.logger.Errorf("JWT format validation failed for %s: %v", config.Type, err)
			return TokenRetrievalResult{Error: err, Token: ""}
		}
	} else if !config.AllowOpaqueTokens {
		if err := validator.ValidateJWTFormat(token, config.Type); err != nil {
			cm.logger.Errorf("Token format validation failed for %s: %v", config.Type, err)
			return TokenRetrievalResult{Error: err, Token: ""}
		}
	}

	// Content validation
	if err := validator.ValidateTokenContent(token, config); err != nil {
		cm.logger.Errorf("Token content validation failed for %s: %v", config.Type, err)
		return TokenRetrievalResult{Error: err, Token: ""}
	}

	cm.logger.Debugf("Successfully validated %s token", config.Type)
	return TokenRetrievalResult{Error: nil, Token: token}
}

// processChunkedToken reconstructs a token from multiple chunks
func (cm *ChunkManager) processChunkedToken(chunks map[int]*sessions.Session, config TokenConfig, compressor TokenCompressor) TokenRetrievalResult {
	if len(chunks) > config.MaxChunks {
		return TokenRetrievalResult{
			Error: &ChunkError{
				Type:    config.Type,
				Reason:  "too many chunks",
				Details: "chunk count exceeds maximum allowed",
			},
			Token: "",
		}
	}

	// Reconstruct token from chunks
	reconstructedToken, err := cm.reconstructTokenFromChunks(chunks, config)
	if err != nil {
		cm.logger.Errorf("Failed to reconstruct %s token from chunks: %v", config.Type, err)
		return TokenRetrievalResult{Error: err, Token: ""}
	}

	// Try decompression
	decompressedToken := compressor.DecompressToken(reconstructedToken)
	if decompressedToken != reconstructedToken {
		cm.logger.Debugf("Decompressed reconstructed %s token", config.Type)
		return cm.validateToken(decompressedToken, config)
	}

	return cm.validateToken(reconstructedToken, config)
}

// reconstructTokenFromChunks reconstructs a token from ordered chunks
func (cm *ChunkManager) reconstructTokenFromChunks(chunks map[int]*sessions.Session, config TokenConfig) (string, error) {
	if len(chunks) == 0 {
		return "", &ChunkError{
			Type:    config.Type,
			Reason:  "no chunks found",
			Details: "no chunk sessions available for reconstruction",
		}
	}

	// Find the maximum chunk index to determine total chunks
	maxIndex := -1
	for index := range chunks {
		if index > maxIndex {
			maxIndex = index
		}
	}

	if maxIndex < 0 {
		return "", &ChunkError{
			Type:    config.Type,
			Reason:  "invalid chunk indices",
			Details: "no valid chunk indices found",
		}
	}

	// Reconstruct token by concatenating chunks in order
	var tokenBuilder strings.Builder
	for i := 0; i <= maxIndex; i++ {
		chunk, exists := chunks[i]
		if !exists || chunk == nil {
			return "", &ChunkError{
				Type:    config.Type,
				Reason:  "missing chunk",
				Details: fmt.Sprintf("chunk %d is missing", i),
			}
		}

		chunkValue, ok := chunk.Values["value"].(string)
		if !ok || chunkValue == "" {
			return "", &ChunkError{
				Type:    config.Type,
				Reason:  "empty chunk",
				Details: fmt.Sprintf("chunk %d has no value", i),
			}
		}

		tokenBuilder.WriteString(chunkValue)
	}

	reconstructed := tokenBuilder.String()
	if reconstructed == "" {
		return "", &ChunkError{
			Type:    config.Type,
			Reason:  "empty reconstructed token",
			Details: "all chunks were present but resulted in empty token",
		}
	}

	cm.logger.Debugf("Successfully reconstructed %s token from %d chunks (length: %d)",
		config.Type, len(chunks), len(reconstructed))

	return reconstructed, nil
}

// CleanupExpiredSessions removes expired sessions from the session map
func (cm *ChunkManager) CleanupExpiredSessions() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	now := time.Now()

	// Only cleanup if enough time has passed
	if now.Sub(cm.lastCleanup) < time.Hour {
		return
	}

	cm.lastCleanup = now
	cleaned := 0

	for key, entry := range cm.sessionMap {
		if now.After(entry.ExpiresAt) || now.Sub(entry.LastUsed) > cm.sessionTTL {
			delete(cm.sessionMap, key)
			cleaned++
		}
	}

	if cleaned > 0 {
		cm.logger.Debugf("Cleaned up %d expired sessions", cleaned)
	}
}

// StoreSession stores a session in the session map with expiration tracking
func (cm *ChunkManager) StoreSession(key string, session *sessions.Session) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// CRITICAL FIX: Aggressive session limit enforcement
	currentLocal := len(cm.sessionMap)
	currentGlobal := atomic.LoadInt64(&globalSessionCount)

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

	if shouldEvict {
		// Find oldest sessions to remove
		type sessionAge struct {
			key      string
			lastUsed time.Time
		}

		sessions := make([]sessionAge, 0, currentLocal)
		for k, entry := range cm.sessionMap {
			sessions = append(sessions, sessionAge{key: k, lastUsed: entry.LastUsed})
		}

		// Sort by last used time (oldest first)
		for i := 0; i < len(sessions)-1; i++ {
			for j := i + 1; j < len(sessions); j++ {
				if sessions[i].lastUsed.After(sessions[j].lastUsed) {
					sessions[i], sessions[j] = sessions[j], sessions[i]
				}
			}
		}

		// Remove excess sessions
		excessCount := currentLocal - targetCapacity
		if excessCount < 0 {
			excessCount = 0
		}

		removedCount := int64(0)
		for i := 0; i < excessCount && i < len(sessions); i++ {
			delete(cm.sessionMap, sessions[i].key)
			removedCount++
		}

		if removedCount > 0 {
			atomic.AddInt64(&globalSessionCount, -removedCount)
		}
	}

	cm.sessionMap[key] = &SessionEntry{
		Session:   session,
		ExpiresAt: time.Now().Add(cm.sessionTTL),
		LastUsed:  time.Now(),
	}
	atomic.AddInt64(&globalSessionCount, 1) // CRITICAL FIX: Track addition
}

// GetSession retrieves a session from the session map
func (cm *ChunkManager) GetSession(key string) *sessions.Session {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	entry, exists := cm.sessionMap[key]
	if !exists {
		return nil
	}

	// Update last used time
	entry.LastUsed = time.Now()
	return entry.Session
}

// TokenCompressor interface for token compression operations
type TokenCompressor interface {
	CompressToken(token string) string
	DecompressToken(compressed string) string
}

// ChunkError represents errors that occur during chunk operations
type ChunkError struct {
	Type    string
	Reason  string
	Details string
}

// Error implements the error interface
func (ce *ChunkError) Error() string {
	return fmt.Sprintf("%s chunk error: %s - %s", ce.Type, ce.Reason, ce.Details)
}

// NoOpLogger provides a no-op logger implementation
type NoOpLogger struct{}

// NewNoOpLogger creates a new no-op logger
func NewNoOpLogger() *NoOpLogger {
	return &NoOpLogger{}
}

// Debug does nothing
func (l *NoOpLogger) Debug(msg string) {}

// Debugf does nothing
func (l *NoOpLogger) Debugf(format string, args ...interface{}) {}

// Error does nothing
func (l *NoOpLogger) Error(msg string) {}

// Errorf does nothing
func (l *NoOpLogger) Errorf(format string, args ...interface{}) {}
