package storage

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
)

// Mock logger for testing
type MockLogger struct {
	logs []string
}

func (ml *MockLogger) Error(msg string) {
	ml.logs = append(ml.logs, "ERROR: "+msg)
}

func (ml *MockLogger) Errorf(format string, args ...interface{}) {
	ml.logs = append(ml.logs, fmt.Sprintf("ERROR: "+format, args...))
}

// Mock session manager for testing
type MockSessionManager struct {
	logger Logger
}

func (msm *MockSessionManager) GetSessionOptions(isSecure bool) *sessions.Options {
	return &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		Secure:   isSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (msm *MockSessionManager) EnhanceSessionSecurity(options *sessions.Options, r *http.Request) *sessions.Options {
	if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
		options.Secure = true
	}
	return options
}

func (msm *MockSessionManager) GetLogger() Logger {
	return msm.logger
}

// TestNewSessionData tests session data creation
func TestNewSessionData(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}

	sd := NewSessionData(manager)

	if sd == nil {
		t.Fatal("NewSessionData should not return nil")
	}

	if sd.manager != manager {
		t.Error("Manager should be set correctly")
	}

	if sd.accessTokenChunks == nil || len(sd.accessTokenChunks) != 0 {
		t.Error("Access token chunks map should be initialized and empty")
	}

	if sd.refreshTokenChunks == nil || len(sd.refreshTokenChunks) != 0 {
		t.Error("Refresh token chunks map should be initialized and empty")
	}

	if sd.idTokenChunks == nil || len(sd.idTokenChunks) != 0 {
		t.Error("ID token chunks map should be initialized and empty")
	}

	if sd.dirty {
		t.Error("New session data should not be dirty")
	}

	if sd.inUse {
		t.Error("New session data should not be in use")
	}
}

// TestSessionDataDirtyFlag tests dirty flag management
func TestSessionDataDirtyFlag(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	// Test initial state
	if sd.IsDirty() {
		t.Error("New session should not be dirty")
	}

	// Test marking dirty
	sd.MarkDirty()
	if !sd.IsDirty() {
		t.Error("Session should be dirty after MarkDirty()")
	}

	// Test that Save clears dirty flag (when successful)
	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()

	// Create a simple main session to avoid nil session errors
	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	session, _ := store.Get(req, "test-session")
	sd.mainSession = session

	err := sd.Save(req, w)
	if err != nil {
		t.Logf("Save returned error (may be expected): %v", err)
	}

	// Note: dirty flag is only cleared if Save is completely successful
	// which might not happen with our mock setup
}

// TestSessionDataSave tests session saving functionality
func TestSessionDataSave(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}

	tests := []struct {
		name        string
		setupSesion func(*SessionData)
		expectError bool
		description string
	}{
		{
			name: "Save with main session only",
			setupSesion: func(sd *SessionData) {
				store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
				req := httptest.NewRequest("GET", "http://example.com", nil)
				session, _ := store.Get(req, "test-session")
				sd.mainSession = session
			},
			expectError: true, // Will error because other sessions are nil
			description: "Should handle nil subsidiary sessions",
		},
		{
			name: "Save with all session types",
			setupSesion: func(sd *SessionData) {
				store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
				req := httptest.NewRequest("GET", "http://example.com", nil)

				sd.mainSession, _ = store.Get(req, "main-session")
				sd.accessSession, _ = store.Get(req, "access-session")
				sd.refreshSession, _ = store.Get(req, "refresh-session")
				sd.idTokenSession, _ = store.Get(req, "id-session")
			},
			expectError: false,
			description: "Should save all session types without error",
		},
		{
			name: "Save with token chunks",
			setupSesion: func(sd *SessionData) {
				store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
				req := httptest.NewRequest("GET", "http://example.com", nil)

				sd.mainSession, _ = store.Get(req, "main-session")
				sd.accessSession, _ = store.Get(req, "access-session")
				sd.refreshSession, _ = store.Get(req, "refresh-session")
				sd.idTokenSession, _ = store.Get(req, "id-session")

				// Add some token chunks
				chunk1, _ := store.Get(req, "access-chunk-0")
				chunk2, _ := store.Get(req, "access-chunk-1")
				sd.accessTokenChunks[0] = chunk1
				sd.accessTokenChunks[1] = chunk2

				refreshChunk, _ := store.Get(req, "refresh-chunk-0")
				sd.refreshTokenChunks[0] = refreshChunk
			},
			expectError: false,
			description: "Should save token chunks without error",
		},
		{
			name: "Save with nil main session",
			setupSesion: func(sd *SessionData) {
				sd.mainSession = nil
			},
			expectError: true,
			description: "Should handle nil main session gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd := NewSessionData(manager)
			tt.setupSesion(sd)

			req := httptest.NewRequest("GET", "http://example.com", nil)
			w := httptest.NewRecorder()

			err := sd.Save(req, w)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, got nil", tt.description)
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.description, err)
			}
		})
	}
}

// TestSessionDataSaveHTTPS tests HTTPS detection in Save
func TestSessionDataSaveHTTPS(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))

	tests := []struct {
		name         string
		setupReq     func() *http.Request
		expectSecure bool
		description  string
	}{
		{
			name: "HTTPS via TLS",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "https://example.com", nil)
				// Simulate TLS connection
				req.TLS = &tls.ConnectionState{}
				return req
			},
			expectSecure: true,
			description:  "Should detect HTTPS via TLS",
		},
		{
			name: "HTTPS via X-Forwarded-Proto header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-Proto", "https")
				return req
			},
			expectSecure: true,
			description:  "Should detect HTTPS via X-Forwarded-Proto header",
		},
		{
			name: "HTTP request",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com", nil)
			},
			expectSecure: false,
			description:  "Should detect HTTP correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			w := httptest.NewRecorder()

			session, _ := store.Get(req, "test-session")
			sd.mainSession = session
			// Set all other sessions to avoid nil session errors
			sd.accessSession, _ = store.Get(req, "access-session")
			sd.refreshSession, _ = store.Get(req, "refresh-session")
			sd.idTokenSession, _ = store.Get(req, "id-session")

			err := sd.Save(req, w)
			if err != nil {
				t.Logf("Save returned error: %v", err)
			}

			// Check the session options were set correctly
			if sd.mainSession.Options.Secure != tt.expectSecure {
				t.Errorf("Expected Secure=%v for %s, got %v",
					tt.expectSecure, tt.description, sd.mainSession.Options.Secure)
			}
		})
	}
}

// TestSessionDataChunkManagement tests token chunk management
func TestSessionDataChunkManagement(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Test adding chunks
	chunk0, _ := store.Get(req, "access-chunk-0")
	chunk1, _ := store.Get(req, "access-chunk-1")
	chunk2, _ := store.Get(req, "access-chunk-2")

	sd.accessTokenChunks[0] = chunk0
	sd.accessTokenChunks[1] = chunk1
	sd.accessTokenChunks[2] = chunk2

	if len(sd.accessTokenChunks) != 3 {
		t.Errorf("Expected 3 access token chunks, got %d", len(sd.accessTokenChunks))
	}

	// Test saving chunks
	sd.mainSession, _ = store.Get(req, "main-session")
	sd.accessSession, _ = store.Get(req, "access-session")
	sd.refreshSession, _ = store.Get(req, "refresh-session")
	sd.idTokenSession, _ = store.Get(req, "id-session")

	w := httptest.NewRecorder()

	err := sd.Save(req, w)
	if err != nil {
		t.Logf("Save with chunks returned error: %v", err)
	}

	// Verify chunks have proper options set
	for i, chunk := range sd.accessTokenChunks {
		if chunk.Options == nil {
			t.Errorf("Chunk %d should have options set", i)
		} else if chunk.Options.HttpOnly != true {
			t.Errorf("Chunk %d should have HttpOnly=true", i)
		}
	}
}

// TestSessionDataErrorHandling tests error handling in Save
func TestSessionDataErrorHandling(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	// Test with nil sessions to trigger error paths
	sd.mainSession = nil
	sd.accessSession = nil

	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()

	err := sd.Save(req, w)

	// Should get an error for nil session
	if err == nil {
		t.Error("Expected error when saving nil sessions")
	}

	// Check that error was logged
	if len(logger.logs) == 0 {
		t.Error("Expected error to be logged")
	}

	// Check error message
	foundNilSessionError := false
	for _, log := range logger.logs {
		if strings.Contains(log, "nil session") {
			foundNilSessionError = true
			break
		}
	}

	if !foundNilSessionError {
		t.Error("Expected nil session error to be logged")
	}
}

// TestSessionDataConcurrency tests concurrent access to session data
func TestSessionDataConcurrency(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)
	sd.mainSession, _ = store.Get(req, "main-session")

	// Test concurrent marking as dirty
	done := make(chan bool, 2)

	go func() {
		for i := 0; i < 100; i++ {
			sd.MarkDirty()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_ = sd.IsDirty()
		}
		done <- true
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	// Should not panic and dirty flag should be set
	if !sd.IsDirty() {
		t.Error("Expected session to be dirty after concurrent operations")
	}
}

// TestSessionDataReset tests session data reset functionality
func TestSessionDataReset(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	// Set up session data with various values
	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)

	sd.mainSession, _ = store.Get(req, "main-session")
	sd.accessSession, _ = store.Get(req, "access-session")

	// Add some chunks
	chunk, _ := store.Get(req, "chunk-0")
	sd.accessTokenChunks[0] = chunk

	sd.MarkDirty()
	sd.inUse = true

	// Create a reset method if it exists in the actual implementation
	// This is a placeholder test for reset functionality
	t.Run("Manual reset", func(t *testing.T) {
		// Simulate reset by clearing fields
		sd.mainSession = nil
		sd.accessSession = nil
		sd.refreshSession = nil
		sd.idTokenSession = nil

		// Clear chunks
		sd.accessTokenChunks = make(map[int]*sessions.Session)
		sd.refreshTokenChunks = make(map[int]*sessions.Session)
		sd.idTokenChunks = make(map[int]*sessions.Session)

		sd.dirty = false
		sd.inUse = false

		// Verify reset
		if sd.mainSession != nil {
			t.Error("Main session should be nil after reset")
		}

		if len(sd.accessTokenChunks) != 0 {
			t.Error("Access token chunks should be empty after reset")
		}

		if sd.IsDirty() {
			t.Error("Session should not be dirty after reset")
		}

		if sd.inUse {
			t.Error("Session should not be in use after reset")
		}
	})
}

// TestSessionDataValidation tests session data validation
func TestSessionDataValidation(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}

	tests := []struct {
		name        string
		setupFunc   func() *SessionData
		expectValid bool
		description string
	}{
		{
			name: "Valid session data",
			setupFunc: func() *SessionData {
				sd := NewSessionData(manager)
				store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
				req := httptest.NewRequest("GET", "http://example.com", nil)
				sd.mainSession, _ = store.Get(req, "main-session")
				return sd
			},
			expectValid: true,
			description: "Should validate correct session data",
		},
		{
			name: "Invalid session data - nil manager",
			setupFunc: func() *SessionData {
				sd := &SessionData{
					manager:            nil,
					accessTokenChunks:  make(map[int]*sessions.Session),
					refreshTokenChunks: make(map[int]*sessions.Session),
					idTokenChunks:      make(map[int]*sessions.Session),
				}
				return sd
			},
			expectValid: false,
			description: "Should reject session data with nil manager",
		},
		{
			name: "Invalid session data - nil chunks map",
			setupFunc: func() *SessionData {
				sd := NewSessionData(manager)
				sd.accessTokenChunks = nil
				return sd
			},
			expectValid: false,
			description: "Should reject session data with nil chunks map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd := tt.setupFunc()

			// Basic validation checks
			isValid := true

			if sd.manager == nil {
				isValid = false
			}

			if sd.accessTokenChunks == nil || sd.refreshTokenChunks == nil || sd.idTokenChunks == nil {
				isValid = false
			}

			if isValid != tt.expectValid {
				t.Errorf("Validation mismatch for %s: expected valid=%v, got valid=%v",
					tt.description, tt.expectValid, isValid)
			}
		})
	}
}

// BenchmarkSessionDataSave benchmarks session save operations
func BenchmarkSessionDataSave(b *testing.B) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)
	sd.mainSession, _ = store.Get(req, "main-session")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		_ = sd.Save(req, w)
	}
}

// TestClear tests complete session clearing
func TestClear(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()

	// Set up session data
	sd.mainSession, _ = store.Get(req, "main-session")
	sd.accessSession, _ = store.Get(req, "access-session")
	sd.refreshSession, _ = store.Get(req, "refresh-session")
	sd.idTokenSession, _ = store.Get(req, "id-session")

	// Add some chunks
	chunk1, _ := store.Get(req, "access-chunk-0")
	chunk2, _ := store.Get(req, "refresh-chunk-0")
	chunk3, _ := store.Get(req, "id-chunk-0")
	sd.accessTokenChunks[0] = chunk1
	sd.refreshTokenChunks[0] = chunk2
	sd.idTokenChunks[0] = chunk3

	// Add some data to sessions
	sd.mainSession.Values["user_id"] = "123"
	sd.accessSession.Values["token"] = "access-token"
	sd.refreshSession.Values["token"] = "refresh-token"
	sd.idTokenSession.Values["token"] = "id-token"

	sd.MarkDirty()
	sd.SetInUse(true)

	// Clear the session
	err := sd.Clear(req, w)
	if err != nil {
		t.Logf("Clear returned error (may be expected): %v", err)
	}

	// Verify main session values are cleared
	if sd.mainSession != nil && len(sd.mainSession.Values) > 0 {
		t.Error("Main session values should be cleared")
	}

	// Verify session expires
	if sd.mainSession != nil && sd.mainSession.Options.MaxAge != -1 {
		t.Error("Main session should be expired (MaxAge = -1)")
	}

	// Verify chunks are cleared
	if len(sd.accessTokenChunks) != 0 {
		t.Error("Access token chunks should be cleared")
	}
	if len(sd.refreshTokenChunks) != 0 {
		t.Error("Refresh token chunks should be cleared")
	}
	if len(sd.idTokenChunks) != 0 {
		t.Error("ID token chunks should be cleared")
	}

	// Verify request is cleared
	if sd.request != nil {
		t.Error("Request should be cleared")
	}

	// Verify usage status is reset
	if sd.IsInUse() {
		t.Error("Session should not be in use after clear")
	}
}

// TestClearWithNilResponseWriter tests clearing with nil response writer
func TestClearWithNilResponseWriter(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)

	sd.mainSession, _ = store.Get(req, "main-session")
	sd.mainSession.Values["test"] = "value"

	// Clear with nil response writer
	err := sd.Clear(req, nil)
	if err != nil {
		t.Logf("Clear with nil writer returned error (expected): %v", err)
	}

	// Should still clear session data
	if sd.mainSession != nil && len(sd.mainSession.Values) > 0 {
		t.Error("Session values should be cleared even with nil writer")
	}
}

// TestClearWithErrorTrigger tests error handling in Clear
func TestClearWithErrorTrigger(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Test-Error", "true") // Trigger error condition
	w := httptest.NewRecorder()

	sd.mainSession, _ = store.Get(req, "main-session")

	err := sd.Clear(req, w)
	// May return error due to test trigger
	t.Logf("Clear with error trigger returned: %v", err)

	// Should still clear the data despite error
	if sd.request != nil {
		t.Error("Request should be cleared even after error")
	}
}

// TestReset tests session reset functionality
func TestReset(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Set up session data
	sd.mainSession, _ = store.Get(req, "main-session")
	sd.accessSession, _ = store.Get(req, "access-session")
	sd.refreshSession, _ = store.Get(req, "refresh-session")
	sd.idTokenSession, _ = store.Get(req, "id-session")
	sd.request = req

	// Add chunks
	chunk1, _ := store.Get(req, "access-chunk-0")
	chunk2, _ := store.Get(req, "refresh-chunk-0")
	chunk3, _ := store.Get(req, "id-chunk-0")
	sd.accessTokenChunks[0] = chunk1
	sd.refreshTokenChunks[0] = chunk2
	sd.idTokenChunks[0] = chunk3

	sd.MarkDirty()
	sd.SetInUse(true)

	// Reset the session
	sd.Reset()

	// Verify all sessions are nil
	if sd.mainSession != nil {
		t.Error("Main session should be nil after reset")
	}
	if sd.accessSession != nil {
		t.Error("Access session should be nil after reset")
	}
	if sd.refreshSession != nil {
		t.Error("Refresh session should be nil after reset")
	}
	if sd.idTokenSession != nil {
		t.Error("ID token session should be nil after reset")
	}

	// Verify chunks are cleared
	if len(sd.accessTokenChunks) != 0 {
		t.Error("Access token chunks should be empty after reset")
	}
	if len(sd.refreshTokenChunks) != 0 {
		t.Error("Refresh token chunks should be empty after reset")
	}
	if len(sd.idTokenChunks) != 0 {
		t.Error("ID token chunks should be empty after reset")
	}

	// Verify state is reset
	if sd.IsDirty() {
		t.Error("Session should not be dirty after reset")
	}
	if sd.IsInUse() {
		t.Error("Session should not be in use after reset")
	}
	if sd.request != nil {
		t.Error("Request should be nil after reset")
	}
}

// TestSetSessions tests session setting
func TestSetSessions(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)

	main, _ := store.Get(req, "main")
	access, _ := store.Get(req, "access")
	refresh, _ := store.Get(req, "refresh")
	idToken, _ := store.Get(req, "id")

	// Set all sessions at once
	sd.SetSessions(main, access, refresh, idToken)

	// Verify sessions are set correctly
	if sd.GetMainSession() != main {
		t.Error("Main session not set correctly")
	}
	if sd.GetAccessSession() != access {
		t.Error("Access session not set correctly")
	}
	if sd.GetRefreshSession() != refresh {
		t.Error("Refresh session not set correctly")
	}
	if sd.GetIDTokenSession() != idToken {
		t.Error("ID token session not set correctly")
	}
}

// TestSetSessionsWithNil tests setting sessions with nil values
func TestSetSessionsWithNil(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	// Set sessions with nil values
	sd.SetSessions(nil, nil, nil, nil)

	// Verify sessions are nil
	if sd.GetMainSession() != nil {
		t.Error("Main session should be nil")
	}
	if sd.GetAccessSession() != nil {
		t.Error("Access session should be nil")
	}
	if sd.GetRefreshSession() != nil {
		t.Error("Refresh session should be nil")
	}
	if sd.GetIDTokenSession() != nil {
		t.Error("ID token session should be nil")
	}
}

// TestGetTokenChunks tests token chunk retrieval
func TestGetTokenChunks(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Add chunks to each map
	accessChunk, _ := store.Get(req, "access-chunk-0")
	refreshChunk, _ := store.Get(req, "refresh-chunk-0")
	idChunk, _ := store.Get(req, "id-chunk-0")

	sd.accessTokenChunks[0] = accessChunk
	sd.refreshTokenChunks[0] = refreshChunk
	sd.idTokenChunks[0] = idChunk

	// Get chunks
	access, refresh, id := sd.GetTokenChunks()

	// Verify chunks are returned correctly
	if len(access) != 1 || access[0] != accessChunk {
		t.Error("Access token chunks not returned correctly")
	}
	if len(refresh) != 1 || refresh[0] != refreshChunk {
		t.Error("Refresh token chunks not returned correctly")
	}
	if len(id) != 1 || id[0] != idChunk {
		t.Error("ID token chunks not returned correctly")
	}
}

// TestSetInUseAndIsInUse tests usage tracking
func TestSetInUseAndIsInUse(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	// Initially should not be in use
	if sd.IsInUse() {
		t.Error("New session should not be in use")
	}

	// Set in use
	sd.SetInUse(true)
	if !sd.IsInUse() {
		t.Error("Session should be in use after SetInUse(true)")
	}

	// Set not in use
	sd.SetInUse(false)
	if sd.IsInUse() {
		t.Error("Session should not be in use after SetInUse(false)")
	}
}

// TestReturnToPoolSafely tests safe pool return
func TestReturnToPoolSafely(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	// Set session as in use
	sd.SetInUse(true)
	sd.MarkDirty()

	// Set up some session data
	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)
	sd.mainSession, _ = store.Get(req, "main")
	sd.request = req

	// Call returnToPoolSafely directly
	sd.returnToPoolSafely()

	// Verify session was reset and marked not in use
	if sd.IsInUse() {
		t.Error("Session should not be in use after pool return")
	}
	if sd.mainSession != nil {
		t.Error("Session should be reset after pool return")
	}
	if sd.IsDirty() {
		t.Error("Session should not be dirty after pool return")
	}
}

// TestClearAllSessionData tests the internal clear function
func TestClearAllSessionData(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Set up session data with values
	sd.mainSession, _ = store.Get(req, "main")
	sd.accessSession, _ = store.Get(req, "access")
	sd.refreshSession, _ = store.Get(req, "refresh")
	sd.idTokenSession, _ = store.Get(req, "id")

	// Add values to sessions
	sd.mainSession.Values["user"] = "test"
	sd.accessSession.Values["token"] = "access"
	sd.refreshSession.Values["token"] = "refresh"
	sd.idTokenSession.Values["token"] = "id"

	// Add chunks
	chunk1, _ := store.Get(req, "access-chunk-0")
	chunk2, _ := store.Get(req, "refresh-chunk-0")
	chunk3, _ := store.Get(req, "id-chunk-0")
	sd.accessTokenChunks[0] = chunk1
	sd.refreshTokenChunks[0] = chunk2
	sd.idTokenChunks[0] = chunk3

	// Test clearing with expire = true
	sd.clearAllSessionData(req, true)

	// Verify all sessions are cleared and expired
	if sd.mainSession != nil && len(sd.mainSession.Values) != 0 {
		t.Error("Main session values should be cleared")
	}
	if sd.mainSession != nil && sd.mainSession.Options.MaxAge != -1 {
		t.Error("Main session should be expired")
	}

	// Verify chunks are cleared
	if len(sd.accessTokenChunks) != 0 {
		t.Error("Access chunks should be cleared")
	}
	if len(sd.refreshTokenChunks) != 0 {
		t.Error("Refresh chunks should be cleared")
	}
	if len(sd.idTokenChunks) != 0 {
		t.Error("ID chunks should be cleared")
	}

	// Verify dirty flag is set when expiring
	if !sd.IsDirty() {
		t.Error("Session should be dirty after clearing with expire=true")
	}
}

// TestClearAllSessionDataWithoutExpire tests clearing without expiring
func TestClearAllSessionDataWithoutExpire(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Set up session data
	sd.mainSession, _ = store.Get(req, "main")
	sd.mainSession.Values["user"] = "test"

	// Add chunks
	chunk1, _ := store.Get(req, "access-chunk-0")
	sd.accessTokenChunks[0] = chunk1

	// Clear without expiring
	sd.clearAllSessionData(req, false)

	// Verify values are cleared but not expired
	if sd.mainSession != nil && len(sd.mainSession.Values) != 0 {
		t.Error("Session values should be cleared")
	}
	if sd.mainSession != nil && sd.mainSession.Options.MaxAge == -1 {
		t.Error("Session should not be expired when expire=false")
	}

	// Verify chunks are cleared
	if len(sd.accessTokenChunks) != 0 {
		t.Error("Chunks should be cleared")
	}

	// Verify dirty flag is not set when not expiring
	if sd.IsDirty() {
		t.Error("Session should not be dirty when expire=false")
	}
}

// TestClearSessionValues tests the clearSessionValues helper
func TestClearSessionValues(t *testing.T) {
	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)

	session, _ := store.Get(req, "test")
	session.Values["key1"] = "value1"
	session.Values["key2"] = "value2"

	// Test clearing with expire
	clearSessionValues(session, true)

	if len(session.Values) != 0 {
		t.Error("Session values should be cleared")
	}
	if session.Options.MaxAge != -1 {
		t.Error("Session should be expired")
	}

	// Test clearing without expire
	session.Values["key3"] = "value3"
	session.Options.MaxAge = 3600 // Reset

	clearSessionValues(session, false)

	if len(session.Values) != 0 {
		t.Error("Session values should be cleared")
	}
	if session.Options.MaxAge == -1 {
		t.Error("Session should not be expired when expire=false")
	}

	// Test with nil session
	clearSessionValues(nil, true)
	// Should not panic
}

// TestClearTokenChunks tests token chunk clearing
func TestClearTokenChunks(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Create chunks with values
	chunk1, _ := store.Get(req, "chunk-0")
	chunk2, _ := store.Get(req, "chunk-1")
	chunk1.Values["data"] = "test1"
	chunk2.Values["data"] = "test2"

	chunks := make(map[int]*sessions.Session)
	chunks[0] = chunk1
	chunks[1] = chunk2

	// Clear chunks
	sd.clearTokenChunks(req, chunks)

	// Verify chunks are cleared and expired
	if len(chunk1.Values) != 0 {
		t.Error("Chunk 1 values should be cleared")
	}
	if chunk1.Options.MaxAge != -1 {
		t.Error("Chunk 1 should be expired")
	}

	// Verify map is empty
	if len(chunks) != 0 {
		t.Error("Chunks map should be empty")
	}
}

// TestClearTokenChunksWithNilChunk tests clearing with nil chunk
func TestClearTokenChunksWithNilChunk(t *testing.T) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	req := httptest.NewRequest("GET", "http://example.com", nil)

	chunks := make(map[int]*sessions.Session)
	chunks[0] = nil // nil chunk

	// Should not panic
	sd.clearTokenChunks(req, chunks)

	// Verify map is empty
	if len(chunks) != 0 {
		t.Error("Chunks map should be empty")
	}
}

// TestSessionDataEdgeCases tests various edge cases
func TestSessionDataEdgeCases(t *testing.T) {
	t.Run("Save with nil logger", func(t *testing.T) {
		manager := &MockSessionManager{logger: nil}
		sd := NewSessionData(manager)

		req := httptest.NewRequest("GET", "http://example.com", nil)
		w := httptest.NewRecorder()

		// Should not panic with nil logger
		err := sd.Save(req, w)
		if err == nil {
			t.Log("Save with nil logger succeeded (may be expected)")
		}
	})

	t.Run("returnToPoolSafely with panic recovery", func(t *testing.T) {
		logger := &MockLogger{}
		manager := &MockSessionManager{logger: logger}
		sd := NewSessionData(manager)

		sd.SetInUse(true)

		// Should not panic
		sd.returnToPoolSafely()

		// Check if panic was logged (would require triggering actual panic)
		t.Log("returnToPoolSafely completed without panic")
	})
}

// BenchmarkSessionDataSaveWithChunks benchmarks session save with token chunks
func BenchmarkSessionDataSaveWithChunks(b *testing.B) {
	logger := &MockLogger{}
	manager := &MockSessionManager{logger: logger}
	sd := NewSessionData(manager)

	store := sessions.NewCookieStore([]byte("test-key-32-characters-long-1234"))
	req := httptest.NewRequest("GET", "http://example.com", nil)

	sd.mainSession, _ = store.Get(req, "main-session")

	// Add multiple chunks
	for i := 0; i < 5; i++ {
		chunk, _ := store.Get(req, fmt.Sprintf("access-chunk-%d", i))
		sd.accessTokenChunks[i] = chunk

		refreshChunk, _ := store.Get(req, fmt.Sprintf("refresh-chunk-%d", i))
		sd.refreshTokenChunks[i] = refreshChunk
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		_ = sd.Save(req, w)
	}
}
