// Package chunking provides chunk serialization functionality
package chunking

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ChunkSerializer handles serialization and deserialization of token chunks
type ChunkSerializer struct {
	logger Logger
}

// NewChunkSerializer creates a new chunk serializer
func NewChunkSerializer(logger Logger) *ChunkSerializer {
	return &ChunkSerializer{
		logger: logger,
	}
}

// SerializeTokenToChunks splits a token into chunks suitable for cookie storage
func (cs *ChunkSerializer) SerializeTokenToChunks(token string, config TokenConfig) ([]ChunkData, error) {
	if token == "" {
		return nil, fmt.Errorf("cannot serialize empty token")
	}

	if len(token) < config.MinLength {
		return nil, fmt.Errorf("token too short: %d < %d", len(token), config.MinLength)
	}

	if len(token) > config.MaxLength {
		return nil, fmt.Errorf("token too long: %d > %d", len(token), config.MaxLength)
	}

	// Calculate optimal chunk size
	chunkSize := config.MaxChunkSize
	if chunkSize <= 0 {
		chunkSize = maxCookieSize
	}

	// Estimate number of chunks needed
	estimatedChunks := (len(token) + chunkSize - 1) / chunkSize
	if estimatedChunks > config.MaxChunks {
		return nil, fmt.Errorf("token requires too many chunks: %d > %d", estimatedChunks, config.MaxChunks)
	}

	// Split token into chunks
	chunks := make([]ChunkData, 0, estimatedChunks)
	remaining := token

	chunkIndex := 0
	for len(remaining) > 0 {
		if chunkIndex >= config.MaxChunks {
			return nil, fmt.Errorf("exceeded maximum chunk count during serialization")
		}

		// Determine chunk size for this iteration
		currentChunkSize := chunkSize
		if len(remaining) < currentChunkSize {
			currentChunkSize = len(remaining)
		}

		// Extract chunk
		chunkContent := remaining[:currentChunkSize]
		remaining = remaining[currentChunkSize:]

		// Create chunk data
		chunkData := ChunkData{
			Index:    chunkIndex,
			Content:  chunkContent,
			Total:    estimatedChunks, // Will be updated after all chunks are created
			Checksum: cs.calculateChecksum(chunkContent),
		}

		chunks = append(chunks, chunkData)
		chunkIndex++
	}

	// Update total count in all chunks
	actualChunks := len(chunks)
	for i := range chunks {
		chunks[i].Total = actualChunks
	}

	cs.logger.Debugf("Serialized %s token into %d chunks", config.Type, len(chunks))
	return chunks, nil
}

// DeserializeTokenFromChunks reconstructs a token from chunk data
func (cs *ChunkSerializer) DeserializeTokenFromChunks(chunks []ChunkData, config TokenConfig) (string, error) {
	if len(chunks) == 0 {
		return "", fmt.Errorf("no chunks provided for deserialization")
	}

	if len(chunks) > config.MaxChunks {
		return "", fmt.Errorf("too many chunks: %d > %d", len(chunks), config.MaxChunks)
	}

	// Validate chunk consistency
	expectedTotal := chunks[0].Total
	for i, chunk := range chunks {
		if chunk.Total != expectedTotal {
			return "", fmt.Errorf("chunk %d has inconsistent total count: %d != %d", i, chunk.Total, expectedTotal)
		}
	}

	if len(chunks) != expectedTotal {
		return "", fmt.Errorf("chunk count mismatch: got %d, expected %d", len(chunks), expectedTotal)
	}

	// Sort chunks by index
	orderedChunks := make([]ChunkData, expectedTotal)
	for _, chunk := range chunks {
		if chunk.Index < 0 || chunk.Index >= expectedTotal {
			return "", fmt.Errorf("invalid chunk index: %d (total: %d)", chunk.Index, expectedTotal)
		}

		if orderedChunks[chunk.Index].Content != "" {
			return "", fmt.Errorf("duplicate chunk index: %d", chunk.Index)
		}

		orderedChunks[chunk.Index] = chunk
	}

	// Verify all chunks are present
	for i, chunk := range orderedChunks {
		if chunk.Content == "" {
			return "", fmt.Errorf("missing chunk at index: %d", i)
		}

		// Verify checksum
		expectedChecksum := cs.calculateChecksum(chunk.Content)
		if chunk.Checksum != expectedChecksum {
			return "", fmt.Errorf("chunk %d checksum mismatch", i)
		}
	}

	// Reconstruct token
	var tokenBuilder strings.Builder
	tokenBuilder.Grow(len(chunks) * config.MaxChunkSize) // Pre-allocate capacity

	for _, chunk := range orderedChunks {
		tokenBuilder.WriteString(chunk.Content)
	}

	reconstructedToken := tokenBuilder.String()

	// Final validation
	if len(reconstructedToken) < config.MinLength {
		return "", fmt.Errorf("reconstructed token too short: %d < %d", len(reconstructedToken), config.MinLength)
	}

	if len(reconstructedToken) > config.MaxLength {
		return "", fmt.Errorf("reconstructed token too long: %d > %d", len(reconstructedToken), config.MaxLength)
	}

	cs.logger.Debugf("Deserialized %s token from %d chunks (length: %d)", config.Type, len(chunks), len(reconstructedToken))
	return reconstructedToken, nil
}

// EncodeChunk encodes chunk data for cookie storage
func (cs *ChunkSerializer) EncodeChunk(chunk ChunkData) (string, error) {
	// Create a simple format: index:total:checksum:content
	encoded := fmt.Sprintf("%d:%d:%s:%s", chunk.Index, chunk.Total, chunk.Checksum, chunk.Content)

	// Base64 encode the entire chunk for safe cookie storage
	return base64.StdEncoding.EncodeToString([]byte(encoded)), nil
}

// DecodeChunk decodes chunk data from cookie storage
func (cs *ChunkSerializer) DecodeChunk(encoded string) (ChunkData, error) {
	// Base64 decode
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ChunkData{}, fmt.Errorf("failed to base64 decode chunk: %w", err)
	}

	// Parse the format: index:total:checksum:content
	parts := strings.SplitN(string(decoded), ":", 4)
	if len(parts) != 4 {
		return ChunkData{}, fmt.Errorf("invalid chunk format: expected 4 parts, got %d", len(parts))
	}

	var index, total int
	if _, err := fmt.Sscanf(parts[0], "%d", &index); err != nil {
		return ChunkData{}, fmt.Errorf("invalid chunk index: %w", err)
	}

	if _, err := fmt.Sscanf(parts[1], "%d", &total); err != nil {
		return ChunkData{}, fmt.Errorf("invalid chunk total: %w", err)
	}

	checksum := parts[2]
	content := parts[3]

	return ChunkData{
		Index:    index,
		Total:    total,
		Content:  content,
		Checksum: checksum,
	}, nil
}

// ValidateChunkIntegrity validates the integrity of chunk data
func (cs *ChunkSerializer) ValidateChunkIntegrity(chunk ChunkData) error {
	if chunk.Index < 0 {
		return fmt.Errorf("negative chunk index: %d", chunk.Index)
	}

	if chunk.Total <= 0 {
		return fmt.Errorf("invalid total chunks: %d", chunk.Total)
	}

	if chunk.Index >= chunk.Total {
		return fmt.Errorf("chunk index %d exceeds total %d", chunk.Index, chunk.Total)
	}

	if chunk.Content == "" {
		return fmt.Errorf("empty chunk content at index %d", chunk.Index)
	}

	if chunk.Checksum == "" {
		return fmt.Errorf("empty chunk checksum at index %d", chunk.Index)
	}

	// Verify checksum
	expectedChecksum := cs.calculateChecksum(chunk.Content)
	if chunk.Checksum != expectedChecksum {
		return fmt.Errorf("chunk %d checksum mismatch: expected %s, got %s",
			chunk.Index, expectedChecksum, chunk.Checksum)
	}

	return nil
}

// calculateChecksum calculates a simple checksum for chunk content
func (cs *ChunkSerializer) calculateChecksum(content string) string {
	// Simple checksum using length and first/last characters
	if len(content) == 0 {
		return "empty"
	}

	checksum := fmt.Sprintf("len%d", len(content))
	if len(content) >= 1 {
		checksum += fmt.Sprintf("_first%d", int(content[0]))
	}
	if len(content) >= 2 {
		checksum += fmt.Sprintf("_last%d", int(content[len(content)-1]))
	}

	return checksum
}

// ChunkData represents a single chunk of token data
type ChunkData struct {
	Index    int    // Position of this chunk in the sequence
	Total    int    // Total number of chunks for this token
	Content  string // The actual chunk content
	Checksum string // Simple checksum for integrity verification
}

// EstimateChunkCount estimates how many chunks a token will need
func (cs *ChunkSerializer) EstimateChunkCount(tokenLength int, chunkSize int) int {
	if chunkSize <= 0 {
		chunkSize = maxCookieSize
	}

	return (tokenLength + chunkSize - 1) / chunkSize
}

// MaxTokenSizeForChunks calculates the maximum token size that can fit in the given number of chunks
func (cs *ChunkSerializer) MaxTokenSizeForChunks(maxChunks int, chunkSize int) int {
	if chunkSize <= 0 {
		chunkSize = maxCookieSize
	}

	return maxChunks * chunkSize
}
