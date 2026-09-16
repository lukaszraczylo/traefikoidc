package traefikoidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testHeaderWriter records the response headers exactly as they are at
// WriteHeader time, so tests can verify header fields are set before the
// status line is committed (setting a header after WriteHeader has no effect
// on the wire).
type testHeaderWriter struct {
	status       http.Header
	headerAtCode http.Header
	code         int
}

func (w *testHeaderWriter) Header() http.Header         { return w.status }
func (w *testHeaderWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *testHeaderWriter) WriteHeader(code int) {
	w.code = code
	w.headerAtCode = w.status.Clone()
}

// TestWriteBearerError_SetsCacheControlBeforeWriteHeader guards the R125 fix
// to bearer_auth.go writeBearerError: the Cache-Control: no-store header
// (the R101 no-cache contract for 401/403/429/503 rejections) was set
// AFTER WriteHeader, so it was never actually sent on the wire — a cached
// 429 could be replayed after the penalty box expired. It must be set
// before the status line is committed.
func TestWriteBearerError_SetsCacheControlBeforeWriteHeader(t *testing.T) {
	w := &testHeaderWriter{status: http.Header{}}
	tObj := &TraefikOidc{}
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/api", nil)

	tObj.writeBearerError(w, req, newBearerError(bearerErrForbidden, "denied"))

	if w.code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.code, http.StatusForbidden)
	}
	if got := w.headerAtCode.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control at WriteHeader = %q, want \"no-store\" (header set after WriteHeader is never sent)", got)
	}
}

// TestChunkManager_OpaqueTokenAbove8KReadable guards the R125 fix to
// session_chunk_manager.go validateTokenSize: the read path hard-capped
// opaque (dot-less) tokens at 8KB while the write path (session.go
// SetAccessToken) accepts and chunk-stores them up to config.MaxLength.
// An opaque token between 8KB and MaxLength was therefore written but
// permanently rejected on read ("" -> forced re-auth). The read cap must
// accept whatever the write path accepts.
func TestChunkManager_OpaqueTokenAbove8KReadable(t *testing.T) {
	cm := &ChunkManager{}
	// > the old 8KB opaque cap, < AccessTokenConfig.MaxLength (100KB).
	token := strings.Repeat("A", 9*1024)
	if err := cm.validateTokenSize(token, AccessTokenConfig); err != nil {
		t.Fatalf("opaque token of %d bytes (within write MaxLength) must be readable, got: %v", len(token), err)
	}
}

// TestSharedTransportPool_CleanupResetsCountAndStaysUsable guards the R125
// fix to http_client_pool.go Cleanup: Cleanup canceled the singleton
// cleanup goroutine without restarting it and left clientCount unreset. A
// reused pool then had a permanently-dead cleaner and a stale count
// (corrupting the maxClients soft cap). Cleanup must reset the pool to a
// fully-reusable state.
func TestSharedTransportPool_CleanupResetsCountAndStaysUsable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &SharedTransportPool{
		ctx:        ctx,
		cancel:     cancel,
		transports: map[string]*sharedTransport{},
		maxConns:   20,
		maxClients: 5,
	}

	cfg1 := HTTPClientConfig{DialTimeout: time.Second}
	cfg2 := HTTPClientConfig{DialTimeout: 2 * time.Second}
	_ = p.GetOrCreateTransport(cfg1)
	_ = p.GetOrCreateTransport(cfg2)
	if got := atomic.LoadInt32(&p.clientCount); got != 2 {
		t.Fatalf("clientCount before cleanup = %d, want 2", got)
	}

	p.Cleanup()
	if got := atomic.LoadInt32(&p.clientCount); got != 0 {
		t.Fatalf("clientCount after Cleanup = %d, want 0 (pool must be reusable at full capacity)", got)
	}

	// The pool must still hand out transports after Cleanup.
	if tr := p.GetOrCreateTransport(cfg2); tr == nil {
		t.Fatal("pool must remain usable after Cleanup")
	}
}
