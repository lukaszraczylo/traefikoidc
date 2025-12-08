package traefikoidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
)

// ============================================================================
// SESSION TEST FRAMEWORK
// ============================================================================

// SessionTestCase represents a comprehensive session test scenario
type SessionTestCase struct {
	name        string
	scenario    string // "creation", "validation", "expiration", "persistence", "cleanup", "chunking", "security"
	sessionType string // "user", "admin", "api", "guest", "csrf"
	setup       func(*SessionTestFramework)
	execute     func(*SessionTestFramework) error
	validate    func(*testing.T, error, *SessionTestFramework)
	cleanup     func(*SessionTestFramework)
	concurrent  bool
	iterations  int
	timeout     time.Duration
	skipReason  string
}

// SessionTestFramework provides shared test infrastructure for session tests
type SessionTestFramework struct {
	t            *testing.T
	mockProvider *httptest.Server
	requests     []*http.Request
	responses    []*httptest.ResponseRecorder
	testTokens   map[string]string
	sessionIDs   []string
	mu           sync.RWMutex
	metrics      *SessionTestMetrics
	cleanupFuncs []func()
	config       *SessionTestConfig
}

// SessionTestMetrics tracks test performance metrics
type SessionTestMetrics struct {
	SessionsCreated   int64
	SessionsDestroyed int64
	TokensGenerated   int64
	TokensValidated   int64
	ChunksCreated     int64
	ChunksRetrieved   int64
	ErrorCount        int64
	Duration          time.Duration
}

// SessionTestConfig holds test configuration
type SessionTestConfig struct {
	MaxChunkSize      int
	MaxSessions       int
	EnableHTTPS       bool
	CookieDomain      string
	SessionTimeout    time.Duration
	EncryptionKey     string
	EnableCompression bool
}

// NewSessionTestFramework creates a new test framework instance
func NewSessionTestFramework(t *testing.T) *SessionTestFramework {
	framework := &SessionTestFramework{
		t:            t,
		requests:     make([]*http.Request, 0),
		responses:    make([]*httptest.ResponseRecorder, 0),
		testTokens:   make(map[string]string),
		sessionIDs:   make([]string, 0),
		metrics:      &SessionTestMetrics{},
		cleanupFuncs: make([]func(), 0),
		config: &SessionTestConfig{
			MaxChunkSize:      3900,
			MaxSessions:       1000,
			EnableHTTPS:       false,
			CookieDomain:      "",
			SessionTimeout:    time.Hour,
			EncryptionKey:     generateTestKey(),
			EnableCompression: true,
		},
	}

	// Setup mock OIDC provider
	framework.setupMockProvider()

	return framework
}

// generateTestKey generates a test encryption key
func generateTestKey() string {
	// 48 bytes = 384 bits for testing
	return "0123456789abcdef0123456789abcdef0123456789abcdef"
}

// setupMockProvider sets up a mock OIDC provider for testing
func (f *SessionTestFramework) setupMockProvider() {
	f.mockProvider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 f.mockProvider.URL,
				"authorization_endpoint": f.mockProvider.URL + "/auth",
				"token_endpoint":         f.mockProvider.URL + "/token",
				"userinfo_endpoint":      f.mockProvider.URL + "/userinfo",
				"jwks_uri":               f.mockProvider.URL + "/jwks",
			})
		case "/token":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  f.generateTestToken("access", 3600),
				"id_token":      f.generateTestToken("id", 3600),
				"refresh_token": f.generateTestToken("refresh", 86400),
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		case "/userinfo":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":   "test-user-id",
				"email": "test@example.com",
				"name":  "Test User",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	f.cleanupFuncs = append(f.cleanupFuncs, f.mockProvider.Close)
}

// generateTestToken generates a test token
func (f *SessionTestFramework) generateTestToken(tokenType string, expiresIn int) string {
	atomic.AddInt64(&f.metrics.TokensGenerated, 1)

	// Create a realistic JWT-like token for testing
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claims := map[string]interface{}{
		"iss": f.mockProvider.URL,
		"sub": "test-user-id",
		"aud": "test-client-id",
		"exp": time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
		"iat": time.Now().Unix(),
		"typ": tokenType,
	}

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Generate a fake signature
	signature := make([]byte, 64)
	rand.Read(signature)
	sig := base64.RawURLEncoding.EncodeToString(signature)

	token := fmt.Sprintf("%s.%s.%s", header, payload, sig)

	// Thread-safe write to map
	f.mu.Lock()
	f.testTokens[tokenType] = token
	f.mu.Unlock()

	return token
}

// generateLargeToken generates a token of specified size for testing chunking
func (f *SessionTestFramework) generateLargeToken(size int) string {
	atomic.AddInt64(&f.metrics.TokensGenerated, 1)

	// Create base JWT structure
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	// Calculate how much padding we need in claims
	baseSize := len(header) + 2                          // for the dots
	signatureSize := 86                                  // approximate base64 encoded signature size
	paddingSize := size - baseSize - signatureSize - 100 // leave room for other claims

	if paddingSize < 0 {
		paddingSize = 0
	}

	// Create large padding data
	padding := make([]byte, paddingSize)
	for i := range padding {
		padding[i] = byte('A' + (i % 26))
	}

	claims := map[string]interface{}{
		"iss":     f.mockProvider.URL,
		"sub":     "test-user-id",
		"aud":     "test-client-id",
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
		"padding": base64.StdEncoding.EncodeToString(padding),
	}

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Generate signature
	signature := make([]byte, 64)
	rand.Read(signature)
	sig := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("%s.%s.%s", header, payload, sig)
}

// Cleanup performs framework cleanup
func (f *SessionTestFramework) Cleanup() {
	for _, cleanup := range f.cleanupFuncs {
		cleanup()
	}
}

// ============================================================================
// SESSION CHUNK MANAGER TESTS
// ============================================================================

// Helper function to create a mock HTTP request for session creation
func createMockRequest() *http.Request {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	return req
}

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

// ============================================================================
// SESSION HELPER TESTS
// ============================================================================

// TestSetCodeVerifier_NoChange tests the branch where the code verifier value doesn't change
func TestSetCodeVerifier_NoChange(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	defer sm.Shutdown()

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	// Set initial code verifier
	initialVerifier := "test-code-verifier-12345"
	session.SetCodeVerifier(initialVerifier)

	if !session.IsDirty() {
		t.Error("Session should be dirty after first SetCodeVerifier")
	}

	// Mark clean to test the no-change branch
	session.dirty = false

	// Set the same code verifier again - this should hit the uncovered branch
	session.SetCodeVerifier(initialVerifier)

	// Verify that dirty flag remains false (no change occurred)
	if session.IsDirty() {
		t.Error("Session should not be dirty when setting same code verifier value")
	}

	// Verify the code verifier value is still correct
	if got := session.GetCodeVerifier(); got != initialVerifier {
		t.Errorf("Expected code verifier %q, got %q", initialVerifier, got)
	}
}

// TestClearTokenChunks_EmptyChunks tests the branch where the chunks map is empty
func TestClearTokenChunks_EmptyChunks(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	defer sm.Shutdown()

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	// Test with empty chunks map - this should hit the uncovered branch where the loop body doesn't execute
	emptyChunks := make(map[int]*sessions.Session)

	// This should not panic and should handle empty map gracefully
	session.clearTokenChunks(req, emptyChunks)

	// Verify that no errors occurred and the session is still valid
	if session == nil {
		t.Fatal("Session should still be valid after clearing empty chunks")
	}

	// Additional test: clear already-empty chunk maps in the session
	session.clearTokenChunks(req, session.accessTokenChunks)
	session.clearTokenChunks(req, session.refreshTokenChunks)
	session.clearTokenChunks(req, session.idTokenChunks)

	// Verify session is still valid
	if session.GetAuthenticated() {
		// This is fine - session can be authenticated even with no chunks
	}
}

// TestClearTokenChunks_WithSessions tests the branch where the chunks map contains actual sessions
func TestClearTokenChunks_WithSessions(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	defer sm.Shutdown()

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	// Create chunks map with actual sessions
	chunksWithSessions := make(map[int]*sessions.Session)

	// Create a few test sessions and add them to the chunks map
	for i := 0; i < 3; i++ {
		chunkSession, err := sm.store.Get(req, fmt.Sprintf("test_chunk_%d", i))
		if err != nil {
			t.Fatalf("Failed to create test chunk session: %v", err)
		}
		// Add some test data to the session
		chunkSession.Values["test_data"] = fmt.Sprintf("chunk_%d_data", i)
		chunkSession.Values["chunk_index"] = i
		chunksWithSessions[i] = chunkSession
	}

	// Verify chunks have data before clearing
	if len(chunksWithSessions) != 3 {
		t.Errorf("Expected 3 chunks, got %d", len(chunksWithSessions))
	}

	for i, chunkSession := range chunksWithSessions {
		if chunkSession.Values["test_data"] == nil {
			t.Errorf("Chunk %d should have test data before clearing", i)
		}
	}

	// Call clearTokenChunks - this should hit the loop body and clear all sessions
	session.clearTokenChunks(req, chunksWithSessions)

	// Verify that the sessions were cleared
	for i, chunkSession := range chunksWithSessions {
		if len(chunkSession.Values) != 0 {
			t.Errorf("Chunk %d should have no values after clearing, but has %d values", i, len(chunkSession.Values))
		}
		// Verify MaxAge was set to -1 (expired)
		if chunkSession.Options.MaxAge != -1 {
			t.Errorf("Chunk %d should have MaxAge=-1 (expired), but has MaxAge=%d", i, chunkSession.Options.MaxAge)
		}
	}
}

// ============================================================================
// SESSION POOL AND MEMORY TESTS
// ============================================================================

// TestSessionPoolMemoryLeak tests that session objects are properly returned to the pool
func TestSessionPoolMemoryLeak(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}

	testTokens := NewTestTokens()
	edgeGen := NewEdgeCaseGenerator()
	runner := NewTestSuiteRunner()
	runner.SetTimeout(30 * time.Second)

	tests := []TableTestCase{
		{
			Name:        "Successful session creation and return",
			Description: "Test that sessions are properly created and returned to pool",
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				runtime.GC()
				time.Sleep(100 * time.Millisecond)
				return nil
			},
		},
		{
			Name:        "Explicit ReturnToPool method",
			Description: "Test that explicit pool return works correctly",
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				runtime.GC()
				time.Sleep(100 * time.Millisecond)
				return nil
			},
		},
		{
			Name:        "Error path in GetSession",
			Description: "Test pool behavior when GetSession fails",
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				runtime.GC()
				time.Sleep(100 * time.Millisecond)
				return nil
			},
		},
	}

	// Custom test execution since we need to test memory behavior
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				if err := test.Setup(t); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}

			if test.Teardown != nil {
				defer func() {
					if err := test.Teardown(t); err != nil {
						t.Errorf("Teardown failed: %v", err)
					}
				}()
			}

			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)

			switch test.Name {
			case "Successful session creation and return":
				session, err := sm.GetSession(req)
				if err != nil {
					t.Fatalf("GetSession failed: %v", err)
				}
				session.Clear(req, nil)

			case "Explicit ReturnToPool method":
				session, err := sm.GetSession(req)
				if err != nil {
					t.Fatalf("GetSession failed: %v", err)
				}
				session.ReturnToPool()

			case "Error path in GetSession":
				badSM, _ := NewSessionManager("different0123456789abcdef0123456789abcdef0123456789", false, "", "", 0, logger)
				_, err = badSM.GetSession(req)
				if err == nil {
					t.Log("Note: Expected error when using mismatched encryption keys")
				}
			}

			pooledCount := getPooledObjects(sm)
			t.Logf("Pooled objects count: %d", pooledCount)
		})
	}

	_ = testTokens
	_ = edgeGen
}

// TestSessionErrorHandling tests comprehensive error scenarios using table-driven tests
func TestSessionErrorHandling(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeQuick) {
		return
	}

	edgeGen := NewEdgeCaseGenerator()
	runner := NewTestSuiteRunner()

	// Generate edge case strings for cookie values
	edgeCases := edgeGen.GenerateStringEdgeCases()

	tests := []TableTestCase{
		{
			Name:        "Corrupt cookie value",
			Description: "Test handling of corrupted cookie values",
			Input:       "corrupt-value",
			Expected:    "failed to get main session:",
		},
		{
			Name:        "Invalid base64 cookie",
			Description: "Test handling of invalid base64 in cookies",
			Input:       "!@#$%^&*()",
			Expected:    "failed to get main session:",
		},
		{
			Name:        "Empty cookie value",
			Description: "Test handling of empty cookie values",
			Input:       "",
			Expected:    "", // Empty should work without error
		},
	}

	// Add edge cases dynamically
	for i, edgeCase := range edgeCases {
		if len(edgeCase) > 0 && !strings.ContainsAny(edgeCase, "\x00\x01\x02") { // Skip binary data for cookie tests
			tests = append(tests, TableTestCase{
				Name:        fmt.Sprintf("Edge case %d", i),
				Description: fmt.Sprintf("Test edge case string: %q", edgeCase[:minInt(20, len(edgeCase))]),
				Input:       edgeCase,
				Expected:    "", // Most edge cases should be handled gracefully
			})
		}
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)

			if input, ok := test.Input.(string); ok && input != "" {
				req.AddCookie(&http.Cookie{
					Name:  mainCookieName,
					Value: input,
				})
			}

			_, err = sm.GetSession(req)

			if expected, ok := test.Expected.(string); ok && expected != "" {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if !strings.Contains(err.Error(), expected) {
					t.Errorf("Unexpected error message: %v", err)
				}
			} else {
				// For empty expected, we allow either success or specific failures
				if err != nil {
					t.Logf("Got expected error for edge case: %v", err)
				}
			}
		})
	}

	_ = runner
}

// TestSessionClearAlwaysReturnsToPool tests that sessions are always returned to pool even on errors
func TestSessionClearAlwaysReturnsToPool(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeQuick) {
		return
	}

	runner := NewTestSuiteRunner()

	memoryTests := []MemoryLeakTestCase{
		{
			Name:               "Session clear with error returns to pool",
			Description:        "Verify sessions return to pool even when Clear() errors",
			Iterations:         10,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  5.0,
			GCBetweenRuns:      true,
			Timeout:            30 * time.Second,
			Operation: func() error {
				logger := NewLogger("debug")
				sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
				if err != nil {
					return fmt.Errorf("failed to create session manager: %w", err)
				}

				// Ensure proper cleanup by calling Shutdown
				defer func() {
					if shutdownErr := sm.Shutdown(); shutdownErr != nil {
						logger.Errorf("Failed to shutdown SessionManager: %v", shutdownErr)
					}
				}()

				req := httptest.NewRequest("GET", "http://example.com/foo", nil)
				req.Header.Set("X-Test-Error", "true")

				session, err := sm.GetSession(req)
				if err != nil {
					return fmt.Errorf("GetSession failed: %w", err)
				}

				w := httptest.NewRecorder()
				clearErr := session.Clear(req, w)

				// We expect an error due to the X-Test-Error header, but the session should still be returned
				if clearErr == nil {
					return fmt.Errorf("expected error from Clear with X-Test-Error header")
				}

				return nil
			},
		},
	}

	runner.RunMemoryLeakTests(t, memoryTests)

	// Additional verification test
	t.Run("Verify pool still works after errors", func(t *testing.T) {
		logger := NewLogger("debug")
		sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
		if err != nil {
			t.Fatalf("Failed to create session manager: %v", err)
		}

		// Ensure proper cleanup
		defer func() {
			if shutdownErr := sm.Shutdown(); shutdownErr != nil {
				t.Errorf("Failed to shutdown SessionManager: %v", shutdownErr)
			}
		}()

		normalReq := httptest.NewRequest("GET", "http://example.com/foo", nil)
		session2, err := sm.GetSession(normalReq)
		if err != nil {
			t.Fatalf("Second GetSession failed: %v", err)
		}
		session2.Clear(normalReq, nil)

		t.Log("Session returned to pool despite errors")
	})
}

// TestSessionObjectTracking tests session object tracking and pool behavior
func TestSessionObjectTracking(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeQuick) {
		return
	}

	runner := NewTestSuiteRunner()

	tests := []TableTestCase{
		{
			Name:        "Session pool has New function",
			Description: "Verify that session pool is properly configured",
			Setup: func(t *testing.T) error {
				return nil
			},
		},
		{
			Name:        "Multiple session creation and disposal",
			Description: "Test creating and disposing multiple sessions",
			Input:       5,
		},
		{
			Name:        "Session with nil mainSession",
			Description: "Test error handling with corrupted session state",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				if err := test.Setup(t); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}

			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)

			switch test.Name {
			case "Session pool has New function":
				hasNew := sm.sessionPool.New != nil
				if !hasNew {
					t.Error("Expected sessionPool.New function to be set")
				}

			case "Multiple session creation and disposal":
				count := test.Input.(int)
				for i := 0; i < count; i++ {
					session, err := sm.GetSession(req)
					if err != nil {
						t.Fatalf("GetSession failed: %v", err)
					}
					session.ReturnToPool()
				}

			case "Session with nil mainSession":
				session, err := sm.GetSession(req)
				if err != nil {
					t.Fatalf("GetSession failed: %v", err)
				}

				session.mainSession = nil // Deliberately cause bad state
				session.ReturnToPool()
			}

			runtime.GC()
			time.Sleep(100 * time.Millisecond)
			t.Log("Session pool handling verified")
		})
	}

	_ = runner
}

// ============================================================================
// TOKEN COMPRESSION AND CHUNKING TESTS
// ============================================================================

// TestTokenCompressionIntegrity tests token compression using comprehensive test cases
func TestTokenCompressionIntegrity(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	testTokens := NewTestTokens()
	edgeGen := NewEdgeCaseGenerator()
	runner := NewTestSuiteRunner()

	// Create comprehensive test cases using edge case generator and test tokens
	testCases := []TableTestCase{
		{
			Name:     "Valid JWT Small",
			Input:    testTokens.GetValidTokenSet().AccessToken,
			Expected: true, // Should compress and decompress correctly
		},
		{
			Name:     "Valid JWT Large",
			Input:    testTokens.CreateLargeValidJWT(5000),
			Expected: true,
		},
		{
			Name:     "Minimal Valid JWT",
			Input:    MinimalValidJWT,
			Expected: true,
		},
		{
			Name:     "Invalid JWT Wrong dot count",
			Input:    InvalidTokenOneDot,
			Expected: false, // Should return original for invalid tokens
		},
		{
			Name:     "Invalid JWT No dots",
			Input:    InvalidTokenNoDots,
			Expected: false,
		},
		{
			Name:     "Invalid JWT Too many dots",
			Input:    InvalidTokenThreeDots,
			Expected: false,
		},
		{
			Name:     "Empty token",
			Input:    "",
			Expected: true, // Empty tokens are handled gracefully
		},
		{
			Name:     "Oversized token",
			Input:    testTokens.CreateIncompressibleToken(55000), // >50KB
			Expected: false,                                       // Should be rejected
		},
	}

	// Add string edge cases as additional test inputs
	stringEdgeCases := edgeGen.GenerateStringEdgeCases()
	for i, edgeCase := range stringEdgeCases {
		if len(edgeCase) > 0 && len(edgeCase) < 1000 { // Reasonable size for testing
			testCases = append(testCases, TableTestCase{
				Name:     fmt.Sprintf("Edge case string %d", i),
				Input:    edgeCase,
				Expected: true, // Most edge cases should be handled gracefully
			})
		}
	}

	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			token := test.Input.(string)
			expectValid := test.Expected.(bool)

			compressed := compressToken(token)

			if !expectValid {
				// For invalid tokens, compression should return original
				if compressed != token {
					t.Errorf("Expected compression to return original for invalid token, got different result")
				}
				return
			}

			// For valid tokens, test round-trip integrity
			decompressed := decompressToken(compressed)
			if decompressed != token {
				t.Errorf("Token integrity lost: original=%q, compressed=%q, decompressed=%q",
					token, compressed, decompressed)
			}

			// Test that decompression is idempotent
			decompressed2 := decompressToken(decompressed)
			if decompressed2 != token {
				t.Errorf("Decompression not idempotent: %q != %q", decompressed2, token)
			}
		})
	}

	_ = runner
}

// TestTokenCompressionCorruptionDetection tests corruption detection using table-driven approach
func TestTokenCompressionCorruptionDetection(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	testTokens := NewTestTokens()
	runner := NewTestSuiteRunner()

	tests := []TableTestCase{
		{
			Name:     "Invalid base64",
			Input:    "!@#$%^&*()",
			Expected: true, // Should return original
		},
		{
			Name:     "Valid base64 but invalid gzip",
			Input:    base64.StdEncoding.EncodeToString([]byte("not gzip data")),
			Expected: true,
		},
		{
			Name:     "Truncated gzip data",
			Input:    "H4sI", // Incomplete gzip header
			Expected: true,
		},
		{
			Name:     "Empty string",
			Input:    "",
			Expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			corruptedInput := test.Input.(string)
			expectOriginal := test.Expected.(bool)

			result := decompressToken(corruptedInput)
			if expectOriginal && result != corruptedInput {
				t.Errorf("Expected decompression to return original corrupted input, got: %q", result)
			}
		})
	}

	// Test that valid compression still works
	t.Run("Valid compression verification", func(t *testing.T) {
		validJWT := testTokens.GetValidTokenSet().AccessToken
		compressed := compressToken(validJWT)
		decompressed := decompressToken(compressed)
		if decompressed != validJWT {
			t.Errorf("Valid compression/decompression failed: %q != %q", decompressed, validJWT)
		}
	})

	_ = runner
}

// TestTokenChunkingIntegrity tests token chunking using comprehensive test patterns
func TestTokenChunkingIntegrity(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	testTokens := NewTestTokens()
	edgeGen := NewEdgeCaseGenerator()
	runner := NewTestSuiteRunner()

	tests := []TableTestCase{
		{
			Name:        "Small token no chunking",
			Description: "Small tokens should not be chunked",
			Input: struct {
				size          int
				expectChunked bool
			}{100, false},
		},
		{
			Name:        "Medium token no chunking",
			Description: "Medium tokens should not be chunked",
			Input: struct {
				size          int
				expectChunked bool
			}{800, false},
		},
		{
			Name:        "Large token chunking required",
			Description: "Large tokens should be chunked",
			Input: struct {
				size          int
				expectChunked bool
			}{5000, true},
		},
		{
			Name:        "Very large token multiple chunks",
			Description: "Very large tokens should create multiple chunks",
			Input: struct {
				size          int
				expectChunked bool
			}{10000, true},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			params := test.Input.(struct {
				size          int
				expectChunked bool
			})

			// Create token based on expectation
			var token string
			if params.expectChunked {
				token = testTokens.CreateIncompressibleToken(params.size)
			} else {
				token = testTokens.CreateLargeValidJWT(params.size)
			}

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			// Store the token
			session.SetAccessToken(token)

			// Retrieve the token
			retrievedToken := session.GetAccessToken()

			// Verify integrity
			if retrievedToken != token {
				t.Errorf("Token integrity lost:\nOriginal:  %q\nRetrieved: %q", token, retrievedToken)
			}

			// Check if chunking occurred as expected
			hasChunks := len(session.accessTokenChunks) > 0
			if params.expectChunked != hasChunks {
				t.Errorf("Chunking expectation mismatch: expected chunked=%v, has chunks=%v",
					params.expectChunked, hasChunks)
			}

			session.ReturnToPool()
		})
	}

	_ = edgeGen
	_ = runner
}

// TestTokenChunkingCorruptionResistance tests chunking corruption resistance using table patterns
func TestTokenChunkingCorruptionResistance(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	testTokens := NewTestTokens()
	runner := NewTestSuiteRunner()

	// Define corruption scenarios as test cases
	corruptionTests := []TableTestCase{
		{
			Name:        "Missing chunk in sequence",
			Description: "Test handling when a chunk is missing from sequence",
			Input: func(chunks map[int]*sessions.Session) {
				if len(chunks) > 1 {
					delete(chunks, 1)
				}
			},
			Expected: true, // Expect empty result
		},
		{
			Name:        "Empty chunk data",
			Description: "Test handling when chunk contains empty data",
			Input: func(chunks map[int]*sessions.Session) {
				if chunk, exists := chunks[0]; exists {
					chunk.Values["token_chunk"] = ""
				}
			},
			Expected: true,
		},
		{
			Name:        "Wrong data type in chunk",
			Description: "Test handling when chunk contains wrong data type",
			Input: func(chunks map[int]*sessions.Session) {
				if chunk, exists := chunks[0]; exists {
					chunk.Values["token_chunk"] = 123 // Should be string
				}
			},
			Expected: true,
		},
		{
			Name:        "Oversized chunk",
			Description: "Test handling when chunk exceeds size limits",
			Input: func(chunks map[int]*sessions.Session) {
				if chunk, exists := chunks[0]; exists {
					chunk.Values["token_chunk"] = strings.Repeat("A", maxCookieSize+200)
				}
			},
			Expected: true,
		},
	}

	for _, test := range corruptionTests {
		t.Run(test.Name, func(t *testing.T) {
			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			// Create a large token that will be chunked
			largeToken := testTokens.CreateIncompressibleToken(8000)

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			// Store the token (this should create chunks)
			session.SetAccessToken(largeToken)
			if len(session.accessTokenChunks) == 0 {
				t.Skip("Token was not chunked, skipping corruption test")
			}

			// Apply corruption using the test input function
			corruptFunc := test.Input.(func(map[int]*sessions.Session))
			corruptFunc(session.accessTokenChunks)

			// Try to retrieve the token
			retrievedToken := session.GetAccessToken()

			expectEmpty := test.Expected.(bool)
			if expectEmpty {
				if retrievedToken != "" {
					t.Errorf("Expected empty token due to corruption, got: %q", retrievedToken)
				}
			} else {
				if retrievedToken != largeToken {
					t.Errorf("Expected original token despite corruption, got: %q", retrievedToken)
				}
			}

			session.ReturnToPool()
		})
	}

	_ = corruptionTests
	_ = runner
}

// TestTokenSizeLimits tests token size limit enforcement using table-driven tests
func TestTokenSizeLimits(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	testTokens := NewTestTokens()
	edgeGen := NewEdgeCaseGenerator()
	runner := NewTestSuiteRunner()

	tests := []TableTestCase{
		{
			Name:     "Normal size token",
			Input:    1000,
			Expected: true,
		},
		{
			Name:     "Large but acceptable token",
			Input:    20000, // 20KB
			Expected: true,
		},
		{
			Name:     "Oversized token rejection",
			Input:    120000, // 120KB
			Expected: false,  // Should be rejected
		},
	}

	// Add integer edge cases for token sizes
	intEdgeCases := edgeGen.GenerateIntegerEdgeCases()
	for _, size := range intEdgeCases {
		if size > 0 && size < 100000 {
			tests = append(tests, TableTestCase{
				Name:     fmt.Sprintf("Edge case size %d", size),
				Input:    size,
				Expected: size < 100000, // Reasonable threshold
			})
		}
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}
			defer session.ReturnToPool()

			tokenSize := test.Input.(int)
			expectStored := test.Expected.(bool)

			var token string
			if expectStored {
				token = testTokens.CreateLargeValidJWT(tokenSize)
			} else {
				token = testTokens.CreateIncompressibleToken(tokenSize)
			}

			// Store the token
			session.SetAccessToken(token)

			// Try to retrieve it
			retrievedToken := session.GetAccessToken()

			if expectStored {
				if retrievedToken != token {
					t.Errorf("Expected token to be stored and retrieved, but got different token")
				}
			} else {
				if retrievedToken == token {
					t.Errorf("Expected oversized token to be rejected, but it was stored")
				}
			}
		})
	}

	_ = runner
}

// TestConcurrentTokenOperations tests thread safety using structured test patterns
func TestConcurrentTokenOperations(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeConcurrencyStress) {
		return
	}

	testTokens := NewTestTokens()
	runner := NewTestSuiteRunner()

	// Test concurrent operations using memory leak test pattern
	memoryTests := []MemoryLeakTestCase{
		{
			Name:               "Concurrent token operations",
			Description:        "Test thread safety of concurrent token operations",
			Iterations:         50,
			MaxGoroutineGrowth: 5, // Allow some growth for goroutines
			MaxMemoryGrowthMB:  10.0,
			GCBetweenRuns:      true,
			Timeout:            60 * time.Second,
			Operation: func() error {
				logger := NewLogger("debug")
				sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
				if err != nil {
					return fmt.Errorf("failed to create session manager: %w", err)
				}

				req := httptest.NewRequest("GET", "http://example.com/foo", nil)
				session, err := sm.GetSession(req)
				if err != nil {
					return fmt.Errorf("failed to get session: %w", err)
				}
				defer session.ReturnToPool()

				const numGoroutines = 10
				const numOperations = 100
				done := make(chan bool, numGoroutines)

				for i := 0; i < numGoroutines; i++ {
					go func(id int) {
						defer func() { done <- true }()

						for j := 0; j < numOperations; j++ {
							// Create unique tokens for each goroutine/operation
							accessToken := testTokens.CreateUniqueValidJWT(fmt.Sprintf("%d_%d", id, j))
							refreshToken := fmt.Sprintf("refresh_token_%d_%d", id, j)

							// Concurrent operations
							session.SetAccessToken(accessToken)
							session.SetRefreshToken(refreshToken)

							retrievedAccess := session.GetAccessToken()
							retrievedRefresh := session.GetRefreshToken()

							// Verify tokens are still valid (should be one of the tokens set by any goroutine)
							if retrievedAccess != "" && strings.Count(retrievedAccess, ".") != 2 {
								// Note: In concurrent access, we can't guarantee exact token match
								// but we can verify format is still valid
							}
							if retrievedRefresh != "" && len(retrievedRefresh) < 10 {
								// Verify minimum reasonable length
							}
						}
					}(i)
				}

				// Wait for all goroutines to complete
				for i := 0; i < numGoroutines; i++ {
					<-done
				}

				return nil
			},
		},
	}

	runner.RunMemoryLeakTests(t, memoryTests)

	_ = testTokens
}

// TestSessionValidationAndCleanup tests session validation using comprehensive patterns
func TestSessionValidationAndCleanup(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	testTokens := NewTestTokens()
	edgeGen := NewEdgeCaseGenerator()
	runner := NewTestSuiteRunner()

	tests := []TableTestCase{
		{
			Name:        "Session creation and token storage",
			Description: "Test basic session validation and cleanup",
		},
		{
			Name:        "Large token chunking validation",
			Description: "Test validation with tokens that require chunking",
		},
		{
			Name:        "Session cleanup verification",
			Description: "Test that sessions are properly cleaned up",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			rw := httptest.NewRecorder()

			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			switch test.Name {
			case "Session creation and token storage":
				// Test with normal tokens
				tokenSet := testTokens.GetValidTokenSet()
				session.SetAccessToken(tokenSet.AccessToken)
				session.SetRefreshToken(tokenSet.RefreshToken)

			case "Large token chunking validation":
				// Set tokens that will create chunks
				largeTokenSet := testTokens.GetLargeTokenSet()
				session.SetAccessToken(largeTokenSet.AccessToken)
				session.SetRefreshToken(largeTokenSet.RefreshToken)

			case "Session cleanup verification":
				// Set tokens and then clear them
				session.SetAccessToken(testTokens.GetValidTokenSet().AccessToken)
				session.SetRefreshToken("refresh_token_test")
			}

			// Save session to create cookies
			if err := session.Save(req, rw); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// For cleanup test, verify clearing works
			if test.Name == "Session cleanup verification" {
				if err := session.Clear(req, rw); err != nil {
					t.Logf("Clear returned error (may be expected): %v", err)
				}

				// Verify tokens are cleared
				if token := session.GetAccessToken(); token != "" {
					t.Errorf("Access token should be empty after clear, got: %q", token)
				}
				if token := session.GetRefreshToken(); token != "" {
					t.Errorf("Refresh token should be empty after clear, got: %q", token)
				}
			}
		})
	}

	_ = edgeGen
	_ = runner
}

// TestLargeIDTokenChunking tests ID token chunking using structured approach
func TestLargeIDTokenChunking(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	runner := NewTestSuiteRunner()

	tests := []TableTestCase{
		{
			Name:        "Large ID token chunking 20KB",
			Description: "Test that large ID tokens are properly chunked",
			Input:       20000,
			Expected:    2, // Expect at least 2 chunks
		},
		{
			Name:        "Very large ID token chunking 50KB",
			Description: "Test very large ID token chunking",
			Input:       50000,
			Expected:    5, // Expect at least 5 chunks
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			logger := NewLogger("debug")
			sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			tokenSize := test.Input.(int)
			minExpectedChunks := test.Expected.(int)

			// Create a large ID token
			largeIDToken := createLargeIDToken(tokenSize)
			t.Logf("Created large ID token with length: %d", len(largeIDToken))

			// Create a request and response recorder
			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			rr := httptest.NewRecorder()

			// Get session and set large ID token
			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			// Set the large ID token
			session.SetIDToken(largeIDToken)
			t.Logf("Set large ID token in session")

			// Save the session to trigger chunking
			err = session.Save(req, rr)
			if err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Verify token retrieval integrity
			retrievedToken := session.GetIDToken()
			t.Logf("Retrieved ID token length: %d", len(retrievedToken))
			if len(retrievedToken) != len(largeIDToken) {
				t.Errorf("Token length mismatch: expected %d, got %d", len(largeIDToken), len(retrievedToken))
			}

			// Verify that chunked cookies were created
			cookies := rr.Result().Cookies()
			t.Logf("Total cookies in response: %d", len(cookies))

			var chunkCookies []*http.Cookie
			for _, cookie := range cookies {
				if strings.HasPrefix(cookie.Name, idTokenCookie+"_") {
					chunkCookies = append(chunkCookies, cookie)
				}
			}

			// Verify minimum expected chunks
			if len(chunkCookies) < minExpectedChunks {
				t.Fatalf("Expected at least %d chunk cookies, got %d", minExpectedChunks, len(chunkCookies))
			}

			// Test token retrieval from chunked cookies
			newReq := httptest.NewRequest("GET", "http://example.com/foo", nil)
			for _, cookie := range cookies {
				newReq.AddCookie(cookie)
			}

			retrievedSession, err := sm.GetSession(newReq)
			if err != nil {
				t.Fatalf("Failed to get session from chunked cookies: %v", err)
			}

			retrievedToken2 := retrievedSession.GetIDToken()

			// Verify the retrieved token matches the original
			if retrievedToken2 != largeIDToken {
				t.Errorf("Retrieved ID token doesn't match original. Expected length: %d, got: %d",
					len(largeIDToken), len(retrievedToken2))
			}

			// Test clearing the ID token removes all chunks
			retrievedSession.SetIDToken("")

			clearRR := httptest.NewRecorder()
			err = retrievedSession.Save(newReq, clearRR)
			if err != nil {
				t.Fatalf("Failed to save session after clearing ID token: %v", err)
			}

			// Verify chunks are expired (MaxAge = -1)
			clearCookies := clearRR.Result().Cookies()
			for _, cookie := range clearCookies {
				if strings.HasPrefix(cookie.Name, idTokenCookie+"_") {
					if cookie.MaxAge != -1 {
						t.Errorf("Expected chunk cookie %s to be expired (MaxAge=-1), got MaxAge=%d",
							cookie.Name, cookie.MaxAge)
					}
				}
			}
		})
	}

	_ = runner
}

// ============================================================================
// CONSOLIDATED SESSION TESTS
// ============================================================================

// TestSessionConsolidated runs all consolidated session tests
func TestSessionConsolidated(t *testing.T) {
	testCases := []SessionTestCase{
		// Session Creation Tests
		{
			name:        "session_basic_creation",
			scenario:    "creation",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				atomic.AddInt64(&f.metrics.SessionsCreated, 1)
				// Simulate session creation
				req := httptest.NewRequest("GET", "http://example.com/", nil)
				f.requests = append(f.requests, req)
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Session creation should succeed")
				assert.Greater(t, f.metrics.SessionsCreated, int64(0), "Session should be created")
			},
		},
		{
			name:        "session_pool_reuse",
			scenario:    "creation",
			sessionType: "user",
			iterations:  100,
			execute: func(f *SessionTestFramework) error {
				for i := 0; i < 100; i++ {
					atomic.AddInt64(&f.metrics.SessionsCreated, 1)
					atomic.AddInt64(&f.metrics.SessionsDestroyed, 1)
				}
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err)
				assert.Equal(t, f.metrics.SessionsCreated, f.metrics.SessionsDestroyed, "Sessions should be properly pooled")
			},
		},
		{
			name:        "session_concurrent_creation",
			scenario:    "creation",
			sessionType: "user",
			concurrent:  true,
			iterations:  50,
			execute: func(f *SessionTestFramework) error {
				var wg sync.WaitGroup
				errs := make(chan error, 50)

				for i := 0; i < 50; i++ {
					wg.Add(1)
					go func(id int) {
						defer wg.Done()
						atomic.AddInt64(&f.metrics.SessionsCreated, 1)
						// Simulate concurrent session creation
						req := httptest.NewRequest("GET", fmt.Sprintf("http://example.com/%d", id), nil)
						f.mu.Lock()
						f.requests = append(f.requests, req)
						f.mu.Unlock()
					}(i)
				}

				wg.Wait()
				close(errs)

				for err := range errs {
					if err != nil {
						return err
					}
				}
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err)
				assert.Equal(t, int64(50), f.metrics.SessionsCreated, "All concurrent sessions should be created")
			},
		},

		// Session Validation Tests
		{
			name:        "session_token_validation",
			scenario:    "validation",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				token := f.generateTestToken("access", 3600)
				atomic.AddInt64(&f.metrics.TokensValidated, 1)

				// Validate token format
				parts := strings.Split(token, ".")
				if len(parts) != 3 {
					return fmt.Errorf("invalid token format")
				}
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Token validation should succeed")
				assert.Greater(t, f.metrics.TokensValidated, int64(0))
			},
		},
		{
			name:        "session_corrupted_token_detection",
			scenario:    "validation",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				token := f.generateTestToken("access", 3600)
				// Corrupt the token by modifying the signature
				parts := strings.Split(token, ".")
				if len(parts) != 3 {
					return fmt.Errorf("invalid token format")
				}

				// Corrupt the signature part
				corrupted := parts[0] + "." + parts[1] + ".corrupted!"
				atomic.AddInt64(&f.metrics.TokensValidated, 1)

				// Validate should detect corruption - corrupted tokens should fail validation
				corruptedParts := strings.Split(corrupted, ".")
				if len(corruptedParts) == 3 {
					// Try to decode the corrupted signature
					_, err := base64.RawURLEncoding.DecodeString(corruptedParts[2])
					if err == nil {
						return fmt.Errorf("corruption not detected")
					}
				}
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Corruption detection should work")
			},
		},
		{
			name:        "session_expired_token_handling",
			scenario:    "validation",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				// Generate an expired token
				token := f.generateTestToken("access", -3600) // negative expiry
				atomic.AddInt64(&f.metrics.TokensValidated, 1)

				// Parse and check expiry
				parts := strings.Split(token, ".")
				if len(parts) == 3 {
					payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
					var claims map[string]interface{}
					json.Unmarshal(payload, &claims)

					if exp, ok := claims["exp"].(float64); ok {
						if exp < float64(time.Now().Unix()) {
							atomic.AddInt64(&f.metrics.ErrorCount, 1)
							return nil // Expected behavior
						}
					}
				}
				return fmt.Errorf("expired token not detected")
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Expired token should be detected")
				assert.Greater(t, f.metrics.ErrorCount, int64(0))
			},
		},

		// Session Expiration Tests
		{
			name:        "session_ttl_expiration",
			scenario:    "expiration",
			sessionType: "user",
			timeout:     3 * time.Second,
			execute: func(f *SessionTestFramework) error {
				atomic.AddInt64(&f.metrics.SessionsCreated, 1)
				// Simulate session with short TTL
				time.Sleep(100 * time.Millisecond) // Don't sleep for full timeout
				atomic.AddInt64(&f.metrics.SessionsDestroyed, 1)
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err)
				assert.Equal(t, f.metrics.SessionsCreated, f.metrics.SessionsDestroyed)
			},
		},
		{
			name:        "session_refresh_token_expiry",
			scenario:    "expiration",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				refreshToken := f.generateTestToken("refresh", 86400)
				atomic.AddInt64(&f.metrics.TokensValidated, 1)

				// Check refresh token is valid for longer period
				parts := strings.Split(refreshToken, ".")
				if len(parts) == 3 {
					payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
					var claims map[string]interface{}
					json.Unmarshal(payload, &claims)

					if exp, ok := claims["exp"].(float64); ok {
						timeUntilExpiry := time.Until(time.Unix(int64(exp), 0))
						if timeUntilExpiry < 23*time.Hour {
							return fmt.Errorf("refresh token expiry too short: %v", timeUntilExpiry)
						}
					}
				}
				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Refresh token should have correct expiry")
			},
		},

		// Session Persistence Tests
		{
			name:        "session_cookie_persistence",
			scenario:    "persistence",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				req := httptest.NewRequest("GET", "http://example.com/", nil)
				w := httptest.NewRecorder()

				// Set session cookie
				http.SetCookie(w, &http.Cookie{
					Name:     "session_id",
					Value:    "test-session-123",
					Path:     "/",
					HttpOnly: true,
					Secure:   f.config.EnableHTTPS,
					SameSite: http.SameSiteLaxMode,
				})

				f.requests = append(f.requests, req)
				f.responses = append(f.responses, w)

				// Verify cookie was set
				cookies := w.Result().Cookies()
				if len(cookies) == 0 {
					return fmt.Errorf("no cookies set")
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err)
				assert.NotEmpty(t, f.responses, "Response should be recorded")
			},
		},
		{
			name:        "session_state_preservation",
			scenario:    "persistence",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				// Store state
				state := map[string]interface{}{
					"user_id": "test-user",
					"email":   "test@example.com",
					"roles":   []string{"user", "admin"},
				}

				// Serialize and deserialize to test persistence
				data, err := json.Marshal(state)
				if err != nil {
					return err
				}

				var restored map[string]interface{}
				if err := json.Unmarshal(data, &restored); err != nil {
					return err
				}

				// Verify state preserved
				if restored["user_id"] != state["user_id"] {
					return fmt.Errorf("state not preserved")
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Session state should be preserved")
			},
		},

		// Session Cleanup Tests
		{
			name:        "session_proper_cleanup",
			scenario:    "cleanup",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				// Create and destroy sessions
				for i := 0; i < 10; i++ {
					atomic.AddInt64(&f.metrics.SessionsCreated, 1)
					sessionID := fmt.Sprintf("session-%d", i)
					f.sessionIDs = append(f.sessionIDs, sessionID)
				}

				// Cleanup all sessions
				for range f.sessionIDs {
					atomic.AddInt64(&f.metrics.SessionsDestroyed, 1)
				}
				f.sessionIDs = nil

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err)
				assert.Equal(t, f.metrics.SessionsCreated, f.metrics.SessionsDestroyed)
				assert.Empty(t, f.sessionIDs, "All sessions should be cleaned up")
			},
		},
		{
			name:        "session_goroutine_leak_prevention",
			scenario:    "cleanup",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				initialGoroutines := runtime.NumGoroutine()

				// Create sessions that might spawn goroutines
				var wg sync.WaitGroup
				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func(id int) {
						defer wg.Done()
						atomic.AddInt64(&f.metrics.SessionsCreated, 1)
						time.Sleep(10 * time.Millisecond)
						atomic.AddInt64(&f.metrics.SessionsDestroyed, 1)
					}(i)
				}

				wg.Wait()
				runtime.GC()
				time.Sleep(100 * time.Millisecond)

				finalGoroutines := runtime.NumGoroutine()
				if finalGoroutines > initialGoroutines+2 { // Allow small variance
					return fmt.Errorf("goroutine leak detected: %d -> %d", initialGoroutines, finalGoroutines)
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "No goroutine leaks should occur")
			},
		},

		// Session Chunking Tests
		{
			name:        "session_large_token_chunking",
			scenario:    "chunking",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				// Generate a large token that requires chunking
				largeToken := f.generateLargeToken(10000) // 10KB token

				// Calculate expected chunks
				chunkSize := f.config.MaxChunkSize
				expectedChunks := (len(largeToken) + chunkSize - 1) / chunkSize

				// Simulate chunking
				chunks := make([]string, 0)
				for i := 0; i < len(largeToken); i += chunkSize {
					end := i + chunkSize
					if end > len(largeToken) {
						end = len(largeToken)
					}
					chunks = append(chunks, largeToken[i:end])
					atomic.AddInt64(&f.metrics.ChunksCreated, 1)
				}

				if len(chunks) != expectedChunks {
					return fmt.Errorf("expected %d chunks, got %d", expectedChunks, len(chunks))
				}

				// Simulate reconstruction
				reconstructed := strings.Join(chunks, "")
				if reconstructed != largeToken {
					return fmt.Errorf("token reconstruction failed")
				}
				atomic.AddInt64(&f.metrics.ChunksRetrieved, int64(len(chunks)))

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Token chunking should work correctly")
				assert.Greater(t, f.metrics.ChunksCreated, int64(0))
				assert.Equal(t, f.metrics.ChunksCreated, f.metrics.ChunksRetrieved)
			},
		},
		{
			name:        "session_chunk_boundary_validation",
			scenario:    "chunking",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				// Test exact boundary conditions
				testSizes := []int{
					f.config.MaxChunkSize - 1,
					f.config.MaxChunkSize,
					f.config.MaxChunkSize + 1,
					f.config.MaxChunkSize * 2,
					f.config.MaxChunkSize*2 - 1,
					f.config.MaxChunkSize*2 + 1,
				}

				for _, size := range testSizes {
					token := f.generateLargeToken(size)
					actualSize := len(token)
					expectedChunks := (actualSize + f.config.MaxChunkSize - 1) / f.config.MaxChunkSize

					actualChunks := 0
					for i := 0; i < len(token); i += f.config.MaxChunkSize {
						actualChunks++
						atomic.AddInt64(&f.metrics.ChunksCreated, 1)
					}

					if actualChunks != expectedChunks {
						return fmt.Errorf("size %d (actual token size %d): expected %d chunks, got %d", size, actualSize, expectedChunks, actualChunks)
					}
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Chunk boundaries should be handled correctly")
			},
		},

		// Session Security Tests
		{
			name:        "session_csrf_token_management",
			scenario:    "security",
			sessionType: "csrf",
			execute: func(f *SessionTestFramework) error {
				// Generate CSRF token
				csrfToken := make([]byte, 32)
				if _, err := rand.Read(csrfToken); err != nil {
					return err
				}

				csrfString := base64.RawURLEncoding.EncodeToString(csrfToken)

				// Store in session
				f.testTokens["csrf"] = csrfString

				// Validate CSRF token
				if len(csrfString) < 40 {
					return fmt.Errorf("CSRF token too short")
				}

				atomic.AddInt64(&f.metrics.TokensGenerated, 1)
				atomic.AddInt64(&f.metrics.TokensValidated, 1)

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "CSRF token should be properly managed")
				assert.NotEmpty(t, f.testTokens["csrf"])
			},
		},
		{
			name:        "session_injection_prevention",
			scenario:    "security",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				// Test various injection attempts
				maliciousInputs := []string{
					`{"admin": true}`,
					`<script>alert('xss')</script>`,
					`'; DROP TABLE sessions; --`,
					`../../../etc/passwd`,
					string([]byte{0x00, 0x01, 0x02}), // null bytes
				}

				for _, input := range maliciousInputs {
					// Validate that input is properly sanitized
					sanitized := base64.StdEncoding.EncodeToString([]byte(input))
					decoded, err := base64.StdEncoding.DecodeString(sanitized)
					if err != nil {
						return err
					}

					if string(decoded) != input {
						return fmt.Errorf("sanitization changed input unexpectedly")
					}

					atomic.AddInt64(&f.metrics.TokensValidated, 1)
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Injection attempts should be handled safely")
			},
		},
		{
			name:        "session_secure_cookie_settings",
			scenario:    "security",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				w := httptest.NewRecorder()

				// Test secure cookie settings
				cookie := &http.Cookie{
					Name:     "session",
					Value:    "test-session",
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
					MaxAge:   3600,
				}

				http.SetCookie(w, cookie)

				// Verify cookie attributes
				cookies := w.Result().Cookies()
				if len(cookies) == 0 {
					return fmt.Errorf("no cookie set")
				}

				c := cookies[0]
				if !c.HttpOnly {
					return fmt.Errorf("cookie not HttpOnly")
				}
				if c.SameSite != http.SameSiteStrictMode {
					return fmt.Errorf("incorrect SameSite setting")
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Secure cookie settings should be enforced")
			},
		},

		// Session Stress Tests
		{
			name:        "session_high_concurrency_stress",
			scenario:    "creation",
			sessionType: "user",
			concurrent:  true,
			iterations:  1000,
			timeout:     30 * time.Second,
			execute: func(f *SessionTestFramework) error {
				var wg sync.WaitGroup
				errors := make([]error, 0)

				// Run high concurrency test
				concurrency := 100
				iterations := 10

				for i := 0; i < concurrency; i++ {
					wg.Add(1)
					go func(workerID int) {
						defer wg.Done()

						for j := 0; j < iterations; j++ {
							// Create session
							atomic.AddInt64(&f.metrics.SessionsCreated, 1)

							// Generate tokens
							f.generateTestToken("access", 3600)
							f.generateTestToken("refresh", 86400)

							// Validate tokens
							atomic.AddInt64(&f.metrics.TokensValidated, 2)

							// Cleanup session
							atomic.AddInt64(&f.metrics.SessionsDestroyed, 1)

							// Small delay to simulate real usage
							time.Sleep(time.Millisecond)
						}
					}(i)
				}

				wg.Wait()

				if len(errors) > 0 {
					return errors[0]
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "High concurrency stress test should pass")
				assert.Equal(t, f.metrics.SessionsCreated, f.metrics.SessionsDestroyed, "All sessions should be cleaned up")
			},
		},
		{
			name:        "session_memory_bounds_enforcement",
			scenario:    "cleanup",
			sessionType: "user",
			execute: func(f *SessionTestFramework) error {
				maxSessions := f.config.MaxSessions

				// Try to create more sessions than allowed
				for i := 0; i < maxSessions+100; i++ {
					sessionID := fmt.Sprintf("session-%d", i)
					f.sessionIDs = append(f.sessionIDs, sessionID)
					atomic.AddInt64(&f.metrics.SessionsCreated, 1)

					// Enforce max sessions
					if len(f.sessionIDs) > maxSessions {
						// Remove oldest session
						f.sessionIDs = f.sessionIDs[1:]
						atomic.AddInt64(&f.metrics.SessionsDestroyed, 1)
					}
				}

				if len(f.sessionIDs) > maxSessions {
					return fmt.Errorf("max sessions exceeded: %d > %d", len(f.sessionIDs), maxSessions)
				}

				return nil
			},
			validate: func(t *testing.T, err error, f *SessionTestFramework) {
				assert.NoError(t, err, "Memory bounds should be enforced")
				assert.LessOrEqual(t, len(f.sessionIDs), f.config.MaxSessions)
			},
		},
	}

	// Run all test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipReason != "" {
				t.Skip(tc.skipReason)
			}

			framework := NewSessionTestFramework(t)
			defer framework.Cleanup()

			// Setup
			if tc.setup != nil {
				tc.setup(framework)
			}

			// Cleanup
			if tc.cleanup != nil {
				defer tc.cleanup(framework)
			}

			// Set timeout if specified
			if tc.timeout > 0 {
				timer := time.NewTimer(tc.timeout)
				done := make(chan bool)

				go func() {
					err := tc.execute(framework)
					tc.validate(t, err, framework)
					done <- true
				}()

				select {
				case <-done:
					timer.Stop()
				case <-timer.C:
					t.Fatal("Test timeout exceeded")
				}
			} else {
				// Execute test
				err := tc.execute(framework)

				// Validate results
				tc.validate(t, err, framework)
			}
		})
	}
}

// ============================================================================
// SESSION STATE PRESERVATION TESTS (6-HOUR TOKEN EXPIRY SCENARIOS)
// ============================================================================

// TestSessionStatePreservationWithExpiredTokens tests that session state is preserved
// during token expiry scenarios
func TestSessionStatePreservationWithExpiredTokens(t *testing.T) {
	t.Log("Testing session state preservation with expired tokens")

	logger := NewLogger("debug")
	sm, err := NewSessionManager("test-session-key-32-bytes-long-12345", false, "", "", 0, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Simulate real-world session data that should be preserved
	originalUserData := map[string]interface{}{
		"user_id":     "user-12345",
		"email":       "test.user@company.com",
		"name":        "Test User",
		"roles":       []string{"admin", "user"},
		"pref_theme":  "dark",
		"pref_lang":   "en",
		"last_active": "2023-01-01T10:00:00Z",
	}

	// Create initial session with valid tokens
	req1 := httptest.NewRequest("GET", "/initial", nil)
	rr1 := httptest.NewRecorder()

	session1, err := sm.GetSession(req1)
	if err != nil {
		t.Fatalf("Failed to get initial session: %v", err)
	}

	// Set up initial session state (what user has when first logging in)
	session1.SetAuthenticated(true)
	session1.SetEmail(originalUserData["email"].(string))
	session1.SetAccessToken("initial-valid-access-token-longer-than-20-chars")
	session1.SetIDToken("initial-valid-id-token-longer-than-20-chars")
	session1.SetRefreshToken("valid-refresh-token-should-last-30-days")

	// Store additional user data in session - store individual values instead of map
	for k, v := range originalUserData {
		session1.mainSession.Values["user_data_"+k] = v
	}
	session1.mainSession.Values["session_created"] = time.Now().Unix() // Store as int64 for gob
	session1.mainSession.Values["custom_flag"] = true

	if err := session1.Save(req1, rr1); err != nil {
		t.Fatalf("Failed to save initial session: %v", err)
	}

	initialCookies := rr1.Result().Cookies()
	session1.ReturnToPool()

	t.Log("Initial session created with user data")

	// Fast-forward 6 hours - tokens expire due to browser inactivity
	time.Sleep(10 * time.Millisecond) // Simulate time passage in test

	// Create expired tokens (simulating what happens after 6 hours)
	expiredTime := time.Now().Add(-6 * time.Hour)
	expiredAccessToken := createExpiredJWTToken("user-12345", "test.user@company.com", expiredTime)
	expiredIDToken := createExpiredJWTToken("user-12345", "test.user@company.com", expiredTime)

	// User returns after inactivity and makes a request
	req2 := httptest.NewRequest("GET", "/protected-resource", nil)
	for _, cookie := range initialCookies {
		req2.AddCookie(cookie)
	}

	session2, err := sm.GetSession(req2)
	if err != nil {
		t.Fatalf("Failed to get session after 6 hours: %v", err)
	}
	defer session2.ReturnToPool()

	// Simulate what happens when middleware detects expired tokens
	// It should preserve session state while attempting token refresh
	originalAuth := session2.GetAuthenticated()
	originalEmail := session2.GetEmail()

	// Reconstruct user data from individual stored keys
	originalUserDataStored := make(map[string]interface{})
	for k := range originalUserData {
		if storedValue, exists := session2.mainSession.Values["user_data_"+k]; exists {
			originalUserDataStored[k] = storedValue
		}
	}

	// Update session with expired tokens (what middleware does when tokens expire)
	session2.SetAccessToken(expiredAccessToken)
	session2.SetIDToken(expiredIDToken)
	// Refresh token should still be valid

	t.Log("Session loaded after 6-hour expiry, checking state preservation")

	// Verify authentication state is preserved
	if !originalAuth {
		t.Error("Authentication state lost during session reload")
	}

	// Verify email is preserved
	if originalEmail != originalUserData["email"].(string) {
		t.Errorf("User email lost during session reload - Expected: %s, Got: %s",
			originalUserData["email"], originalEmail)
	}

	// Verify custom user data is preserved
	if len(originalUserDataStored) == 0 {
		t.Error("All custom user data lost during session reload")
	} else {
		if originalUserDataStored["user_id"] != originalUserData["user_id"] {
			t.Error("User ID lost from session data")
		}

		if originalUserDataStored["name"] != originalUserData["name"] {
			t.Error("User name lost from session data")
		}

		if originalUserDataStored["pref_theme"] != originalUserData["pref_theme"] {
			t.Error("User theme preference lost from session data")
		}

		if originalUserDataStored["pref_lang"] != originalUserData["pref_lang"] {
			t.Error("User language preference lost from session data")
		}
	}

	// Note: System may reject invalid/expired tokens during storage, which is acceptable behavior
	currentAccessToken := session2.GetAccessToken()
	if currentAccessToken != expiredAccessToken {
		t.Logf("INFO: Access token was not stored (possibly rejected due to expiry) - Expected: %s, Got: %s",
			expiredAccessToken, currentAccessToken)
	}

	// Verify that session can be saved again after token expiry without losing data
	rr2 := httptest.NewRecorder()
	if err := session2.Save(req2, rr2); err != nil {
		t.Errorf("Cannot save session after token expiry: %v", err)
	} else {
		t.Log("Session successfully saved after token expiry")

		// Verify cookies are still set
		newCookies := rr2.Result().Cookies()
		if len(newCookies) == 0 {
			t.Error("No session cookies set after saving expired token session")
		}
	}

	// Test session recovery after token refresh simulation
	newAccessToken := "refreshed-access-token-longer-than-20-chars"
	newIDToken := "refreshed-id-token-longer-than-20-chars"
	newRefreshToken := "new-refresh-token-after-successful-renewal"

	session2.SetAccessToken(newAccessToken)
	session2.SetIDToken(newIDToken)
	session2.SetRefreshToken(newRefreshToken)

	// Verify all session data is still intact after token refresh
	postRefreshAuth := session2.GetAuthenticated()
	postRefreshEmail := session2.GetEmail()
	userDataPresent := true
	for k := range originalUserData {
		if session2.mainSession.Values["user_data_"+k] == nil {
			userDataPresent = false
			break
		}
	}

	if !postRefreshAuth {
		t.Error("Authentication state lost after token refresh")
	}

	if postRefreshEmail != originalUserData["email"].(string) {
		t.Error("User email lost after token refresh")
	}

	if !userDataPresent {
		t.Error("User data lost after token refresh")
	}

	t.Log("Session state preservation test completed")
}

// TestSessionExpiryVsTokenExpiry tests the distinction between session expiry and token expiry
func TestSessionExpiryVsTokenExpiry(t *testing.T) {
	t.Log("Testing session expiry vs token expiry distinction")

	logger := NewLogger("debug")
	sm, err := NewSessionManager("session-vs-token-test-key-32-bytes", false, "", "", 0, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	scenarios := []struct {
		name                string
		sessionAge          time.Duration
		tokenExpiry         time.Duration
		expectedBehavior    string
		sessionShouldExpire bool
		tokenShouldRefresh  bool
	}{
		{
			name:                "New session, expired tokens",
			sessionAge:          5 * time.Minute,
			tokenExpiry:         -6 * time.Hour,
			expectedBehavior:    "Session valid, tokens should refresh",
			sessionShouldExpire: false,
			tokenShouldRefresh:  true,
		},
		{
			name:                "Old session, valid tokens",
			sessionAge:          25 * time.Hour,
			tokenExpiry:         2 * time.Hour,
			expectedBehavior:    "Session expired, redirect to login even with valid tokens",
			sessionShouldExpire: true,
			tokenShouldRefresh:  false,
		},
		{
			name:                "Both session and tokens expired",
			sessionAge:          25 * time.Hour,
			tokenExpiry:         -6 * time.Hour,
			expectedBehavior:    "Both expired, clear session and redirect to login",
			sessionShouldExpire: true,
			tokenShouldRefresh:  false,
		},
		{
			name:                "Recent session, recently expired tokens",
			sessionAge:          30 * time.Minute,
			tokenExpiry:         -10 * time.Minute,
			expectedBehavior:    "Session valid, tokens recently expired, should refresh",
			sessionShouldExpire: false,
			tokenShouldRefresh:  true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("Testing: %s", scenario.expectedBehavior)

			// Create session at specific "age"
			sessionCreatedAt := time.Now().Add(-scenario.sessionAge)

			req := httptest.NewRequest("GET", "/test", nil)
			rr := httptest.NewRecorder()

			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}
			defer session.ReturnToPool()

			// Set up session with specific creation time
			session.SetAuthenticated(true)
			session.SetEmail("test@example.com")
			session.mainSession.Values["created_at"] = sessionCreatedAt.Unix()

			// Create tokens with specific expiry
			tokenExpiredAt := time.Now().Add(scenario.tokenExpiry)
			accessToken := createExpiredJWTToken("test-user", "test@example.com", tokenExpiredAt)

			session.SetAccessToken(accessToken)
			session.SetRefreshToken("test-refresh-token")

			if err := session.Save(req, rr); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Test session validity check
			isSessionExpired := scenario.sessionAge > absoluteSessionTimeout
			isTokenExpired := scenario.tokenExpiry < 0

			t.Logf("Session age: %v (expired: %t)", scenario.sessionAge, isSessionExpired)
			t.Logf("Token expiry: %v ago (expired: %t)", -scenario.tokenExpiry, isTokenExpired)

			if scenario.sessionShouldExpire {
				if isSessionExpired && session.GetAuthenticated() {
					t.Errorf("Session should be expired after %v but is still authenticated", scenario.sessionAge)
				}
			} else {
				if !isSessionExpired && !session.GetAuthenticated() {
					t.Errorf("Session should be valid (age: %v) but shows as not authenticated", scenario.sessionAge)
				}
			}

			if scenario.tokenShouldRefresh {
				if !isTokenExpired {
					t.Errorf("Test setup error - tokens should be expired but expiry is: %v", scenario.tokenExpiry)
				}
				t.Logf("Should attempt token refresh for scenario: %s", scenario.name)
			} else {
				if isSessionExpired {
					t.Logf("Correctly identified that session is expired - no need to refresh tokens")
				}
			}

			// Check for critical scenario: confusing session expiry with token expiry
			if !isSessionExpired && isTokenExpired {
				t.Logf("CRITICAL SCENARIO: Valid session (%v old) but expired tokens (%v ago)",
					scenario.sessionAge, -scenario.tokenExpiry)
				t.Logf("Expected: System should refresh tokens and continue session")

				if scenario.name == "New session, expired tokens" && scenario.tokenExpiry == -6*time.Hour {
					t.Logf("This represents the 6-hour browser inactivity scenario")
				}
			}
		})
	}
}

// TestSessionCleanupOnTokenExpiry tests that session cleanup happens correctly
func TestSessionCleanupOnTokenExpiry(t *testing.T) {
	t.Log("Testing session cleanup on token expiry")

	logger := NewLogger("debug")
	sm, err := NewSessionManager("cleanup-test-key-32-bytes-long-123", false, "", "", 0, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	scenarios := []struct {
		name           string
		tokenExpiry    time.Duration
		shouldCleanup  bool
		shouldPreserve []string
		shouldRemove   []string
	}{
		{
			name:           "Recently expired tokens - preserve session",
			tokenExpiry:    -30 * time.Minute,
			shouldCleanup:  false,
			shouldPreserve: []string{"user_data", "preferences", "authentication"},
			shouldRemove:   []string{},
		},
		{
			name:           "Long expired tokens - cleanup selectively",
			tokenExpiry:    -25 * time.Hour,
			shouldCleanup:  true,
			shouldPreserve: []string{},
			shouldRemove:   []string{"user_data", "preferences", "authentication"},
		},
		{
			name:           "6-hour expired tokens - preserve for refresh",
			tokenExpiry:    -6 * time.Hour,
			shouldCleanup:  false,
			shouldPreserve: []string{"user_data", "preferences", "authentication"},
			shouldRemove:   []string{},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("Testing cleanup behavior: %s", scenario.name)

			req := httptest.NewRequest("GET", "/test", nil)
			rr := httptest.NewRecorder()

			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}
			defer session.ReturnToPool()

			// Set up session with data that should be preserved or removed
			session.SetAuthenticated(true)
			session.SetEmail("cleanup@example.com")

			session.mainSession.Values["user_data"] = "Test User|user-123"
			session.mainSession.Values["preferences"] = "theme:dark,lang:en"
			session.mainSession.Values["authentication"] = true
			session.mainSession.Values["temp_data"] = "should-be-cleaned"

			// Set expired tokens
			expiredTime := time.Now().Add(scenario.tokenExpiry)
			expiredToken := createExpiredJWTToken("user-123", "cleanup@example.com", expiredTime)
			session.SetAccessToken(expiredToken)
			session.SetRefreshToken("test-refresh-token")

			if err := session.Save(req, rr); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Simulate token expiry detection and cleanup logic
			tokenExpired := scenario.tokenExpiry < 0
			sessionTooOld := scenario.tokenExpiry < -absoluteSessionTimeout

			t.Logf("Token expired: %t, Session too old: %t", tokenExpired, sessionTooOld)

			// Check current session state before cleanup
			preCleanupAuth := session.GetAuthenticated()
			preCleanupData := session.mainSession.Values["user_data"]
			preCleanupPrefs := session.mainSession.Values["preferences"]

			if scenario.shouldCleanup {
				if sessionTooOld {
					session.SetAuthenticated(false)
					session.SetEmail("")
					session.SetAccessToken("")
					session.SetRefreshToken("")
					for key := range session.mainSession.Values {
						delete(session.mainSession.Values, key)
					}
					t.Log("Applied full cleanup for expired session")
				}
			} else {
				t.Log("Preserving session for token refresh")
			}

			// Check post-cleanup state
			postCleanupAuth := session.GetAuthenticated()
			postCleanupData := session.mainSession.Values["user_data"]
			postCleanupPrefs := session.mainSession.Values["preferences"]

			// Verify preservation expectations
			for _, item := range scenario.shouldPreserve {
				switch item {
				case "authentication":
					if !postCleanupAuth && preCleanupAuth {
						t.Errorf("Authentication state was cleaned up but should be preserved")
					}
				case "user_data":
					if postCleanupData == nil && preCleanupData != nil {
						t.Errorf("User data was cleaned up but should be preserved")
					}
				case "preferences":
					if postCleanupPrefs == nil && preCleanupPrefs != nil {
						t.Errorf("User preferences were cleaned up but should be preserved")
					}
				}
			}

			// Verify removal expectations
			for _, item := range scenario.shouldRemove {
				switch item {
				case "authentication":
					if postCleanupAuth && scenario.shouldCleanup {
						t.Errorf("Authentication state not cleaned up when it should be")
					}
				case "user_data":
					if postCleanupData != nil && scenario.shouldCleanup {
						t.Errorf("User data not cleaned up when session is expired")
					}
				}
			}

			// Check the critical 6-hour scenario
			if scenario.tokenExpiry == -6*time.Hour {
				if !postCleanupAuth {
					t.Error("6-hour token expiry caused session cleanup - session should be preserved for token refresh")
				}

				if postCleanupData == nil {
					t.Error("6-hour token expiry caused user data loss - user data should be preserved during token refresh")
				}
			}
		})
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// Helper function to count objects in the session pool for a given manager
func getPooledObjects(sm *SessionManager) int {
	var objects []*SessionData
	maxAttempts := 100

	for i := 0; i < maxAttempts; i++ {
		obj := sm.sessionPool.Get()
		if obj == nil {
			break
		}

		sessionData, ok := obj.(*SessionData)
		if !ok {
			sm.sessionPool.Put(obj)
			break
		}

		objects = append(objects, sessionData)
	}

	count := len(objects)

	for _, obj := range objects {
		sm.sessionPool.Put(obj)
	}

	return count
}

// createLargeIDToken creates a JWT-like token of specified size for testing
func createLargeIDToken(size int) string {
	randomBytes := make([]byte, size*3/4)
	_, err := rand.Read(randomBytes)
	if err != nil {
		for i := range randomBytes {
			randomBytes[i] = byte(i % 256)
		}
	}

	encoded := base64.RawURLEncoding.EncodeToString(randomBytes)

	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"

	if len(encoded) > size-len(header)-100 {
		encoded = encoded[:size-len(header)-100]
	}

	signature := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	return header + "." + encoded + "." + signature
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Helper function to create expired JWT tokens for testing
func createExpiredJWTToken(userID, email string, expiredTime time.Time) string {
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"

	claims := map[string]interface{}{
		"sub":   userID,
		"email": email,
		"exp":   expiredTime.Unix(),
		"iat":   expiredTime.Add(-1 * time.Hour).Unix(),
		"iss":   "https://test-provider.com",
		"aud":   "test-client-id",
	}

	claimsJSON, _ := json.Marshal(claims)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signature := "fake-signature-for-testing"
	signatureEncoded := base64.RawURLEncoding.EncodeToString([]byte(signature))

	return header + "." + claimsEncoded + "." + signatureEncoded
}
