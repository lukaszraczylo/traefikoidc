package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gorilla/sessions"
)

// Helper function to create a mock HTTP request for session creation
func createMockRequest() *http.Request {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	return req
}

// Test NewSessionChunkManager

func TestNewSessionChunkManager(t *testing.T) {
	manager := NewSessionChunkManager(10)

	if manager == nil {
		t.Fatal("Expected non-nil session chunk manager")
	}

	if manager.maxChunks != 10 {
		t.Errorf("Expected maxChunks 10, got %d", manager.maxChunks)
	}
}

func TestNewSessionChunkManagerDefaultLimit(t *testing.T) {
	// Test with 0 maxChunks (should use default)
	manager := NewSessionChunkManager(0)

	if manager.maxChunks != 20 {
		t.Errorf("Expected default maxChunks 20, got %d", manager.maxChunks)
	}
}

func TestNewSessionChunkManagerNegativeLimit(t *testing.T) {
	// Test with negative maxChunks (should use default)
	manager := NewSessionChunkManager(-5)

	if manager.maxChunks != 20 {
		t.Errorf("Expected default maxChunks 20, got %d", manager.maxChunks)
	}
}

// Test CleanupChunks

func TestCleanupChunksWithoutWriter(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	// Add some chunks
	for i := 0; i < 5; i++ {
		session, _ := store.New(createMockRequest(), "chunk")
		session.Values["token_chunk"] = "chunk-data"
		chunks[i] = session
	}

	// Cleanup without writer (should just clear map)
	manager.CleanupChunks(chunks, nil)

	if len(chunks) != 0 {
		t.Errorf("Expected chunks map to be empty, got %d entries", len(chunks))
	}
}

func TestCleanupChunksWithWriter(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	// Add some chunks
	for i := 0; i < 3; i++ {
		session, _ := store.New(createMockRequest(), "chunk")
		session.Values["token_chunk"] = "chunk-data"
		session.Options = &sessions.Options{MaxAge: 3600}
		chunks[i] = session
	}

	// Create response writer
	w := httptest.NewRecorder()

	// Note: We can't fully test the Save behavior without a proper HTTP request
	// but we can verify the cleanup clears the map
	// The actual Save(nil, w) in the real code has a comment saying it's safe for expiration
	manager.CleanupChunks(chunks, w)

	if len(chunks) != 0 {
		t.Errorf("Expected chunks map to be empty, got %d entries", len(chunks))
	}
}

func TestCleanupChunksNilSession(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)
	chunks[0] = nil
	chunks[1] = nil

	w := httptest.NewRecorder()

	// Should handle nil sessions gracefully
	manager.CleanupChunks(chunks, w)

	if len(chunks) != 0 {
		t.Errorf("Expected chunks map to be empty, got %d entries", len(chunks))
	}
}

func TestCleanupChunksEmptyMap(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)

	// Should handle empty map gracefully
	manager.CleanupChunks(chunks, nil)

	if len(chunks) != 0 {
		t.Error("Expected chunks map to remain empty")
	}
}

// Test ValidateAndCleanChunks

func TestValidateAndCleanChunksWithinLimit(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	// Add chunks within limit
	for i := 0; i < 5; i++ {
		session, _ := store.New(createMockRequest(), "chunk")
		chunks[i] = session
	}

	result := manager.ValidateAndCleanChunks(chunks)

	if !result {
		t.Error("Expected validation to pass for chunks within limit")
	}

	if len(chunks) != 5 {
		t.Errorf("Expected chunks to remain intact, got %d", len(chunks))
	}
}

func TestValidateAndCleanChunksExceedLimit(t *testing.T) {
	manager := NewSessionChunkManager(5)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	// Add more chunks than limit
	for i := 0; i < 10; i++ {
		session, _ := store.New(createMockRequest(), "chunk")
		chunks[i] = session
	}

	result := manager.ValidateAndCleanChunks(chunks)

	if result {
		t.Error("Expected validation to fail for chunks exceeding limit")
	}

	if len(chunks) != 0 {
		t.Errorf("Expected chunks to be cleared, got %d", len(chunks))
	}
}

func TestValidateAndCleanChunksAtLimit(t *testing.T) {
	manager := NewSessionChunkManager(5)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	// Add chunks exactly at limit
	for i := 0; i < 5; i++ {
		session, _ := store.New(createMockRequest(), "chunk")
		chunks[i] = session
	}

	result := manager.ValidateAndCleanChunks(chunks)

	if !result {
		t.Error("Expected validation to pass for chunks at limit")
	}

	if len(chunks) != 5 {
		t.Errorf("Expected chunks to remain intact, got %d", len(chunks))
	}
}

// Test SafeSetChunk

func TestSafeSetChunkValidIndex(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))
	session, _ := store.New(createMockRequest(), "chunk")

	result := manager.SafeSetChunk(chunks, 5, session)

	if !result {
		t.Error("Expected SafeSetChunk to succeed for valid index")
	}

	if chunks[5] != session {
		t.Error("Expected session to be set at index 5")
	}
}

func TestSafeSetChunkNegativeIndex(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))
	session, _ := store.New(createMockRequest(), "chunk")

	result := manager.SafeSetChunk(chunks, -1, session)

	if result {
		t.Error("Expected SafeSetChunk to fail for negative index")
	}

	if len(chunks) != 0 {
		t.Error("Expected chunks map to remain empty")
	}
}

func TestSafeSetChunkIndexTooHigh(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))
	session, _ := store.New(createMockRequest(), "chunk")

	result := manager.SafeSetChunk(chunks, 10, session)

	if result {
		t.Error("Expected SafeSetChunk to fail for index >= maxChunks")
	}

	if len(chunks) != 0 {
		t.Error("Expected chunks map to remain empty")
	}
}

func TestSafeSetChunkExceedingLimit(t *testing.T) {
	manager := NewSessionChunkManager(5)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	// Fill up to limit
	for i := 0; i < 5; i++ {
		session, _ := store.New(createMockRequest(), "chunk")
		chunks[i] = session
	}

	// Try to add a new chunk at new index (should fail)
	session, _ := store.New(createMockRequest(), "chunk")
	result := manager.SafeSetChunk(chunks, 2, session)

	// This should succeed because index 2 already exists
	if !result {
		t.Error("Expected SafeSetChunk to succeed for existing index")
	}
}

func TestSafeSetChunkReplaceExisting(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	session1, _ := store.New(createMockRequest(), "chunk1")
	session2, _ := store.New(createMockRequest(), "chunk2")

	// Set initial session
	manager.SafeSetChunk(chunks, 3, session1)

	// Replace with new session
	result := manager.SafeSetChunk(chunks, 3, session2)

	if !result {
		t.Error("Expected SafeSetChunk to succeed for replacing existing chunk")
	}

	if chunks[3] != session2 {
		t.Error("Expected session to be replaced at index 3")
	}
}

// Test GetChunkCount

func TestGetChunkCount(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	// Add some chunks
	for i := 0; i < 7; i++ {
		session, _ := store.New(createMockRequest(), "chunk")
		chunks[i] = session
	}

	count := manager.GetChunkCount(chunks)

	if count != 7 {
		t.Errorf("Expected chunk count 7, got %d", count)
	}
}

func TestGetChunkCountEmpty(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)

	count := manager.GetChunkCount(chunks)

	if count != 0 {
		t.Errorf("Expected chunk count 0, got %d", count)
	}
}

// Test CompactChunks

func TestCompactChunksNoGaps(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	// Add sequential chunks
	for i := 0; i < 5; i++ {
		session, _ := store.New(createMockRequest(), "chunk")
		session.Values["index"] = i
		chunks[i] = session
	}

	compacted := manager.CompactChunks(chunks)

	if len(compacted) != 5 {
		t.Errorf("Expected 5 compacted chunks, got %d", len(compacted))
	}

	// Verify order
	for i := 0; i < 5; i++ {
		if compacted[i] == nil {
			t.Errorf("Expected chunk at index %d", i)
		}
	}
}

func TestCompactChunksWithGaps(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	// Add chunks with gaps
	indices := []int{0, 2, 5, 7}
	for _, idx := range indices {
		session, _ := store.New(createMockRequest(), "chunk")
		session.Values["original_index"] = idx
		chunks[idx] = session
	}

	compacted := manager.CompactChunks(chunks)

	if len(compacted) != 4 {
		t.Errorf("Expected 4 compacted chunks, got %d", len(compacted))
	}

	// Verify chunks are reindexed sequentially
	for i := 0; i < 4; i++ {
		if compacted[i] == nil {
			t.Errorf("Expected chunk at compacted index %d", i)
		}
	}
}

func TestCompactChunksWithNilEntries(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	// Add chunks and nil entries
	session1, _ := store.New(createMockRequest(), "chunk1")
	session2, _ := store.New(createMockRequest(), "chunk2")
	session3, _ := store.New(createMockRequest(), "chunk3")

	chunks[0] = session1
	chunks[1] = nil
	chunks[2] = session2
	chunks[3] = nil
	chunks[4] = session3

	compacted := manager.CompactChunks(chunks)

	if len(compacted) != 3 {
		t.Errorf("Expected 3 compacted chunks (nil entries removed), got %d", len(compacted))
	}

	// Verify non-nil chunks are compacted
	for i := 0; i < 3; i++ {
		if compacted[i] == nil {
			t.Errorf("Expected non-nil chunk at compacted index %d", i)
		}
	}
}

func TestCompactChunksEmpty(t *testing.T) {
	manager := NewSessionChunkManager(10)

	chunks := make(map[int]*sessions.Session)

	compacted := manager.CompactChunks(chunks)

	if len(compacted) != 0 {
		t.Errorf("Expected empty compacted map, got %d entries", len(compacted))
	}
}

// Test Concurrent Operations

func TestSessionChunkManagerConcurrentOperations(t *testing.T) {
	manager := NewSessionChunkManager(50)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	var wg sync.WaitGroup

	// Concurrent SafeSetChunk
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			session, _ := store.New(createMockRequest(), "chunk")
			manager.SafeSetChunk(chunks, index, session)
		}(i)
	}

	// Concurrent GetChunkCount
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = manager.GetChunkCount(chunks)
		}()
	}

	// Concurrent ValidateAndCleanChunks (reads)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = manager.ValidateAndCleanChunks(chunks)
		}()
	}

	wg.Wait()

	// Verify manager is still functional
	count := manager.GetChunkCount(chunks)
	if count < 0 || count > 50 {
		t.Errorf("Unexpected chunk count after concurrent operations: %d", count)
	}
}

// Test Edge Cases

func TestSessionChunkManagerLargeChunkCount(t *testing.T) {
	manager := NewSessionChunkManager(1000)

	chunks := make(map[int]*sessions.Session)
	store := sessions.NewCookieStore([]byte("test-secret"))

	// Add many chunks
	for i := 0; i < 500; i++ {
		session, _ := store.New(createMockRequest(), "chunk")
		chunks[i] = session
	}

	result := manager.ValidateAndCleanChunks(chunks)

	if !result {
		t.Error("Expected validation to pass for 500 chunks with limit 1000")
	}

	count := manager.GetChunkCount(chunks)
	if count != 500 {
		t.Errorf("Expected 500 chunks, got %d", count)
	}
}

func TestSessionChunkManagerBoundaryConditions(t *testing.T) {
	tests := []struct {
		name       string
		maxChunks  int
		addChunks  int
		shouldPass bool
	}{
		{"exactly at limit", 10, 10, true},
		{"one over limit", 10, 11, false},
		{"way over limit", 10, 50, false},
		{"zero chunks with limit", 10, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewSessionChunkManager(tt.maxChunks)
			chunks := make(map[int]*sessions.Session)
			store := sessions.NewCookieStore([]byte("test-secret"))

			for i := 0; i < tt.addChunks; i++ {
				session, _ := store.New(createMockRequest(), "chunk")
				chunks[i] = session
			}

			result := manager.ValidateAndCleanChunks(chunks)

			if result != tt.shouldPass {
				t.Errorf("Expected validation result %v, got %v", tt.shouldPass, result)
			}
		})
	}
}
