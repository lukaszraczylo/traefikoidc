package traefikoidc

import (
	"fmt"
	"strings"
	"sync"

	"github.com/gorilla/sessions"
)

// TokenConfig holds validation rules for different token types
type TokenConfig struct {
	Type              string
	MinLength         int
	MaxLength         int
	AllowOpaqueTokens bool
	RequireJWTFormat  bool
}

// Predefined configurations for each token type
var (
	AccessTokenConfig = TokenConfig{
		Type:              "access",
		MinLength:         5,
		MaxLength:         50 * 1024,
		AllowOpaqueTokens: true,
		RequireJWTFormat:  false,
	}

	RefreshTokenConfig = TokenConfig{
		Type:              "refresh",
		MinLength:         5,
		MaxLength:         50 * 1024,
		AllowOpaqueTokens: true,
		RequireJWTFormat:  false,
	}

	IDTokenConfig = TokenConfig{
		Type:              "id",
		MinLength:         5,
		MaxLength:         50 * 1024,
		AllowOpaqueTokens: false,
		RequireJWTFormat:  true,
	}
)

// TokenRetrievalResult encapsulates the result of token retrieval
type TokenRetrievalResult struct {
	Token string
	Error error
}

// ChunkManager handles token chunking operations
type ChunkManager struct {
	logger *Logger
	mutex  *sync.RWMutex
}

// NewChunkManager creates a new ChunkManager instance
func NewChunkManager(logger *Logger) *ChunkManager {
	if logger == nil {
		logger = newNoOpLogger()
	}

	return &ChunkManager{
		logger: logger,
		mutex:  &sync.RWMutex{},
	}
}

// GetToken retrieves and validates a token from either single storage or chunks
func (cm *ChunkManager) GetToken(
	singleToken string,
	compressed bool,
	chunks map[int]*sessions.Session,
	config TokenConfig,
) TokenRetrievalResult {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	// Handle single-token storage
	if singleToken != "" {
		return cm.processSingleToken(singleToken, compressed, config)
	}

	// Handle chunked storage
	if len(chunks) == 0 {
		return TokenRetrievalResult{Token: "", Error: nil}
	}

	return cm.processChunkedToken(chunks, config)
}

// processSingleToken handles tokens stored in a single cookie
func (cm *ChunkManager) processSingleToken(token string, compressed bool, config TokenConfig) TokenRetrievalResult {
	// Detect corruption markers
	if isCorruptionMarker(token) {
		err := fmt.Errorf("CRITICAL: %s token contains corruption marker", config.Type)
		cm.logger.Error(err.Error())
		return TokenRetrievalResult{Token: "", Error: err}
	}

	var finalToken string
	if compressed {
		decompressed := decompressToken(token)
		if isCorruptionMarker(decompressed) {
			err := fmt.Errorf("CRITICAL: Decompressed %s token contains corruption marker", config.Type)
			cm.logger.Error(err.Error())
			return TokenRetrievalResult{Token: "", Error: err}
		}
		finalToken = decompressed
	} else {
		finalToken = token
	}

	return cm.validateToken(finalToken, config)
}

// validateToken performs comprehensive token validation
func (cm *ChunkManager) validateToken(token string, config TokenConfig) TokenRetrievalResult {
	// Length validation
	if len(token) < config.MinLength || len(token) > config.MaxLength {
		err := fmt.Errorf("CRITICAL: %s token has invalid length %d", config.Type, len(token))
		cm.logger.Error(err.Error())
		return TokenRetrievalResult{Token: "", Error: err}
	}

	// JWT format validation (if required)
	if config.RequireJWTFormat && !config.AllowOpaqueTokens {
		dotCount := strings.Count(token, ".")
		if dotCount != 2 {
			err := fmt.Errorf("CRITICAL: %s token invalid JWT format (dots: %d)", config.Type, dotCount)
			cm.logger.Error(err.Error())
			return TokenRetrievalResult{Token: "", Error: err}
		}
	} else if config.RequireJWTFormat && config.AllowOpaqueTokens {
		// For tokens that can be either JWT or opaque, validate JWT format only if it has dots
		dotCount := strings.Count(token, ".")
		if dotCount > 0 && dotCount != 2 {
			err := fmt.Errorf("CRITICAL: %s token invalid JWT format (dots: %d)", config.Type, dotCount)
			cm.logger.Error(err.Error())
			return TokenRetrievalResult{Token: "", Error: err}
		}
	}

	return TokenRetrievalResult{Token: token, Error: nil}
}

// processChunkedToken handles tokens stored across multiple chunks
func (cm *ChunkManager) processChunkedToken(chunks map[int]*sessions.Session, config TokenConfig) TokenRetrievalResult {
	// Pre-validate chunk count to prevent excessive memory usage
	if len(chunks) > 50 {
		err := fmt.Errorf("CRITICAL: Too many %s token chunks (%d)", config.Type, len(chunks))
		cm.logger.Error(err.Error())
		return TokenRetrievalResult{Token: "", Error: err}
	}

	// Sequential chunk validation and assembly
	var tokenParts []string
	totalSize := 0

	for i := 0; i < len(chunks); i++ {
		session, ok := chunks[i]
		if !ok {
			err := fmt.Errorf("CRITICAL: %s token chunk %d missing", config.Type, i)
			cm.logger.Error(err.Error())
			return TokenRetrievalResult{Token: "", Error: err}
		}

		chunk, chunkOk := session.Values["token_chunk"].(string)
		if !chunkOk || chunk == "" {
			err := fmt.Errorf("CRITICAL: %s token chunk %d invalid", config.Type, i)
			cm.logger.Error(err.Error())
			return TokenRetrievalResult{Token: "", Error: err}
		}

		if isCorruptionMarker(chunk) {
			err := fmt.Errorf("CRITICAL: %s token chunk %d corrupted", config.Type, i)
			cm.logger.Error(err.Error())
			return TokenRetrievalResult{Token: "", Error: err}
		}

		if len(chunk) > maxCookieSize+100 {
			err := fmt.Errorf("CRITICAL: %s token chunk %d too large", config.Type, i)
			cm.logger.Error(err.Error())
			return TokenRetrievalResult{Token: "", Error: err}
		}

		totalSize += len(chunk)
		if totalSize > config.MaxLength {
			err := fmt.Errorf("CRITICAL: %s token total size exceeds limit", config.Type)
			cm.logger.Error(err.Error())
			return TokenRetrievalResult{Token: "", Error: err}
		}

		tokenParts = append(tokenParts, chunk)
	}

	// Reassemble token
	reassembledToken := strings.Join(tokenParts, "")

	// Check compression flag from first chunk
	compressed, _ := chunks[0].Values["compressed"].(bool)

	if compressed {
		decompressed := decompressToken(reassembledToken)
		if isCorruptionMarker(decompressed) {
			err := fmt.Errorf("CRITICAL: Decompressed chunked %s token corrupted", config.Type)
			cm.logger.Error(err.Error())
			return TokenRetrievalResult{Token: "", Error: err}
		}
		return cm.validateToken(decompressed, config)
	}

	return cm.validateToken(reassembledToken, config)
}
