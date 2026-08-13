package traefikoidc

import (
	"strings"
	"testing"

	"github.com/gorilla/sessions"
)

// TestProcessChunkedTokenDetectsTrailingTruncation guards against silently
// trusting a truncated session token. The recombiner previously used
// len(chunks) as the authoritative total, so losing the trailing chunk(s)
// (browser cookie eviction, dropped Set-Cookie) reassembled the prefix with
// no error. Now the write path stores token_total and the reader rejects a
// count mismatch.
func TestProcessChunkedTokenDetectsTrailingTruncation(t *testing.T) {
	cm := NewChunkManager(NewLogger(DefaultLogLevel))
	config := TokenConfig{
		Type:         "access",
		MinLength:    5,
		MaxLength:    100 * 1024,
		MaxChunks:    25,
		MaxChunkSize: maxCookieSize,
	}

	// 3 chunks were written (token_total=3), but only 2 remain (trailing lost).
	chunks := map[int]*sessions.Session{
		0: {Values: map[interface{}]interface{}{"token_chunk": "aaaa", "token_total": 3}},
		1: {Values: map[interface{}]interface{}{"token_chunk": "bbbb", "token_total": 3}},
	}

	res := cm.GetToken("", false, chunks, config)
	if res.Error == nil {
		t.Fatalf("expected truncation error when chunk count < stored total")
	}
	if !strings.Contains(res.Error.Error(), "chunk count mismatch") {
		t.Fatalf("expected chunk-count-mismatch error, got: %v", res.Error)
	}

	// Control: complete set still assembles (no truncation error).
	full := map[int]*sessions.Session{
		0: {Values: map[interface{}]interface{}{"token_chunk": "aaaa", "token_total": 2}},
		1: {Values: map[interface{}]interface{}{"token_chunk": "bbbb", "token_total": 2}},
	}
	res2 := cm.GetToken("", false, full, config)
	if res2.Error != nil && strings.Contains(res2.Error.Error(), "chunk count mismatch") {
		t.Fatalf("complete chunk set should not report truncation: %v", res2.Error)
	}
}
