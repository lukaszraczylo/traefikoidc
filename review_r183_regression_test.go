package traefikoidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorilla/sessions"
)

// ============================================================================
// R183: chunked-token read scan is bounded
// ---------------------------------------------------------------------------
// getTokenChunkSessions iterated "for i := 0; ; i++" until the first gap,
// doing one securecookie decrypt per candidate chunk cookie, bounded only by
// the ~8KB Cookie header. processChunkedToken only ever uses up to
// MaxChunks (50) and errors above that, so scanning past 50 was pure
// wasted decrypt work (a modest attacker-amplification vector). The scan is
// now capped at MaxChunks; the overflow → error result is unchanged.
// Fail-on-old: with 200 valid chunk cookies the unbounded loop performs
// 201 Get calls; the bounded loop performs at most 51.
func TestR183_ChunkReadScanIsBounded(t *testing.T) {
	spy := &chunkSpyStore{}
	sm := createTestSessionManager(t)
	sm.store = spy

	chunks := make(map[int]*sessions.Session)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sm.getTokenChunkSessions(req, "_t", chunks)

	if got := spy.gets.Load(); got > 51 {
		t.Errorf("chunk read scan performed %d store.Get calls; want at most 51 (MaxChunks+1)", got)
	}
	if len(chunks) < 1 {
		t.Errorf("expected the scan to still load valid chunks; got %d", len(chunks))
	}
}

// The bound must not suppress the >MaxChunks overflow signal: with 200
// valid chunks present, processChunkedToken still sees >50 and errors.
func TestR183_ChunkReadStillDetectsOverflow(t *testing.T) {
	spy := &chunkSpyStore{}
	sm := createTestSessionManager(t)
	sm.store = spy

	chunks := make(map[int]*sessions.Session)
	sm.getTokenChunkSessions(httptest.NewRequest(http.MethodGet, "/", nil), "_t", chunks)
	if len(chunks) != 51 { // indices 0..50: 51 entries, still > MaxChunks=50
		t.Fatalf("expected 51 loaded chunk sessions for overflow detection, got %d", len(chunks))
	}
}

type chunkSpyStore struct {
	gets atomic.Int32
}

func (s *chunkSpyStore) Get(_ *http.Request, name string) (*sessions.Session, error) {
	s.gets.Add(1)
	// Valid chunk cookies for indices 0..200, then a gap.
	idx := -1
	if i := strings.LastIndexByte(name, '_'); i >= 0 {
		_, _ = fmt.Sscanf(name[i+1:], "%d", &idx)
	}
	if idx >= 0 && idx <= 200 {
		return &sessions.Session{Values: make(map[interface{}]interface{})}, nil // IsNew=false
	}
	return &sessions.Session{IsNew: true, Values: make(map[interface{}]interface{})}, nil
}

func (s *chunkSpyStore) New(_ *http.Request, _ string) (*sessions.Session, error) {
	return &sessions.Session{Values: make(map[interface{}]interface{})}, nil
}

func (s *chunkSpyStore) Save(_ *http.Request, _ http.ResponseWriter, _ *sessions.Session) error {
	return nil
}
