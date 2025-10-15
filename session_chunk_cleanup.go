package traefikoidc

import (
	"net/http"
	"sync"

	"github.com/gorilla/sessions"
)

// SessionChunkManager manages session chunks with proper cleanup
type SessionChunkManager struct {
	mu        sync.RWMutex
	maxChunks int
}

// NewSessionChunkManager creates a new session chunk manager
func NewSessionChunkManager(maxChunks int) *SessionChunkManager {
	if maxChunks <= 0 {
		maxChunks = 20 // Reasonable default
	}
	return &SessionChunkManager{
		maxChunks: maxChunks,
	}
}

// CleanupChunks removes all chunks from a map and expires them if writer is provided
func (m *SessionChunkManager) CleanupChunks(chunks map[int]*sessions.Session, w http.ResponseWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Expire all chunk cookies if we have a response writer
	if w != nil {
		for _, session := range chunks {
			if session != nil && session.Options != nil {
				// Set MaxAge to -1 to expire the cookie
				session.Options.MaxAge = -1
				_ = session.Save(nil, w) // Safe to ignore: best effort cleanup of expired chunk
			}
		}
	}

	// Clear the map
	for k := range chunks {
		delete(chunks, k)
	}
}

// ValidateAndCleanChunks validates chunk count and cleans if exceeded
func (m *SessionChunkManager) ValidateAndCleanChunks(chunks map[int]*sessions.Session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(chunks) > m.maxChunks {
		// Too many chunks, clear them all
		for k := range chunks {
			delete(chunks, k)
		}
		return false
	}
	return true
}

// SafeSetChunk safely sets a chunk with bounds checking
func (m *SessionChunkManager) SafeSetChunk(chunks map[int]*sessions.Session, index int, session *sessions.Session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate index bounds
	if index < 0 || index >= m.maxChunks {
		return false
	}

	// Check if adding this would exceed limits
	if len(chunks) >= m.maxChunks && chunks[index] == nil {
		return false
	}

	chunks[index] = session
	return true
}

// GetChunkCount returns the number of chunks in a map
func (m *SessionChunkManager) GetChunkCount(chunks map[int]*sessions.Session) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(chunks)
}

// CompactChunks removes nil entries and reindexes chunks
func (m *SessionChunkManager) CompactChunks(chunks map[int]*sessions.Session) map[int]*sessions.Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	compacted := make(map[int]*sessions.Session)
	index := 0

	// Find max key to know the range
	maxKey := 0
	for k := range chunks {
		if k > maxKey {
			maxKey = k
		}
	}

	// Iterate in order and compact
	for i := 0; i <= maxKey; i++ {
		if session, exists := chunks[i]; exists && session != nil {
			compacted[index] = session
			index++
		}
	}

	return compacted
}
