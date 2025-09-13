package traefikoidc

import (
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
)

func TestSessionChunkManager(t *testing.T) {
	t.Run("cleanup chunks", func(t *testing.T) {
		manager := NewSessionChunkManager(10)

		// Create test chunks
		chunks := make(map[int]*sessions.Session)
		for i := 0; i < 5; i++ {
			chunks[i] = &sessions.Session{
				Options: &sessions.Options{MaxAge: 3600},
			}
		}

		// Cleanup without writer (just clear map)
		manager.CleanupChunks(chunks, nil)

		if len(chunks) != 0 {
			t.Errorf("Expected empty map after cleanup, got %d items", len(chunks))
		}
	})

	t.Run("cleanup with response writer", func(t *testing.T) {
		manager := NewSessionChunkManager(10)
		w := httptest.NewRecorder()

		// Create test chunks
		chunks := make(map[int]*sessions.Session)
		store := sessions.NewCookieStore([]byte("test-key"))

		for i := 0; i < 3; i++ {
			session := sessions.NewSession(store, "test-session")
			session.Options = &sessions.Options{MaxAge: 3600}
			chunks[i] = session
		}

		// Cleanup with writer (expires cookies)
		manager.CleanupChunks(chunks, w)

		if len(chunks) != 0 {
			t.Errorf("Expected empty map after cleanup, got %d items", len(chunks))
		}
	})

	t.Run("validate chunk count", func(t *testing.T) {
		manager := NewSessionChunkManager(5)

		// Within limits
		chunks := make(map[int]*sessions.Session)
		for i := 0; i < 3; i++ {
			chunks[i] = &sessions.Session{}
		}

		if !manager.ValidateAndCleanChunks(chunks) {
			t.Error("Expected validation to pass for chunks within limit")
		}

		// Exceed limits
		for i := 3; i < 10; i++ {
			chunks[i] = &sessions.Session{}
		}

		if manager.ValidateAndCleanChunks(chunks) {
			t.Error("Expected validation to fail for chunks exceeding limit")
		}

		if len(chunks) != 0 {
			t.Errorf("Expected chunks to be cleared after failed validation, got %d", len(chunks))
		}
	})

	t.Run("safe set chunk", func(t *testing.T) {
		manager := NewSessionChunkManager(5)
		chunks := make(map[int]*sessions.Session)

		// Valid index
		session := &sessions.Session{}
		if !manager.SafeSetChunk(chunks, 0, session) {
			t.Error("Expected to set chunk at valid index")
		}

		if chunks[0] != session {
			t.Error("Chunk not set correctly")
		}

		// Invalid index (negative)
		if manager.SafeSetChunk(chunks, -1, session) {
			t.Error("Expected failure for negative index")
		}

		// Invalid index (exceeds max)
		if manager.SafeSetChunk(chunks, 10, session) {
			t.Error("Expected failure for index exceeding max")
		}
	})

	t.Run("chunk count", func(t *testing.T) {
		manager := NewSessionChunkManager(10)
		chunks := make(map[int]*sessions.Session)

		if manager.GetChunkCount(chunks) != 0 {
			t.Error("Expected 0 chunks initially")
		}

		chunks[0] = &sessions.Session{}
		chunks[1] = &sessions.Session{}

		if manager.GetChunkCount(chunks) != 2 {
			t.Errorf("Expected 2 chunks, got %d", manager.GetChunkCount(chunks))
		}
	})

	t.Run("compact chunks", func(t *testing.T) {
		manager := NewSessionChunkManager(10)

		// Create chunks with gaps
		chunks := make(map[int]*sessions.Session)
		chunks[0] = &sessions.Session{ID: "0"}
		chunks[2] = &sessions.Session{ID: "2"}
		chunks[4] = &sessions.Session{ID: "4"}

		compacted := manager.CompactChunks(chunks)

		// Should have 3 entries, indexed 0, 1, 2
		if len(compacted) != 3 {
			t.Errorf("Expected 3 compacted chunks, got %d", len(compacted))
		}

		// Check reindexing - entries should be present and properly indexed
		if compacted[0] == nil || compacted[0].ID != "0" {
			t.Error("First chunk not compacted correctly")
		}
		if compacted[1] == nil || compacted[1].ID != "2" {
			t.Error("Second chunk not compacted correctly")
		}
		if compacted[2] == nil || compacted[2].ID != "4" {
			t.Error("Third chunk not compacted correctly")
		}
	})

	t.Run("max chunks enforcement", func(t *testing.T) {
		manager := NewSessionChunkManager(3)
		chunks := make(map[int]*sessions.Session)

		// Fill up to max
		for i := 0; i < 3; i++ {
			if !manager.SafeSetChunk(chunks, i, &sessions.Session{}) {
				t.Errorf("Failed to set chunk %d within limit", i)
			}
		}

		// Try to add beyond max
		if manager.SafeSetChunk(chunks, 3, &sessions.Session{}) {
			t.Error("Should not allow adding chunk beyond max limit")
		}
	})
}
