package traefikoidc

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/gorilla/sessions"
)

// ============================================================================
// R188: cross-chunk integrity binds chunked-token chunks to one another
// ---------------------------------------------------------------------------
// Each chunk is individually authenticated by its own securecookie MAC, so a
// forged chunk is impossible; but an authentic-but-mixed set (a stale chunk
// from an earlier session combined with the current session's chunks, where
// counts still match) previously assembled silently into a wrong token that
// only surfaced as a downstream JWT validation failure (→ forced re-auth).
// New writes now store a SHA-256 of the assembled chunk string on every
// chunk; processChunkedToken verifies it on read. Absent (old sessions) →
// skipped, preserving backward compatibility.
// Fail-on-old: a mixed set with matching count returns the reassembled
// token; the integrity check now rejects it with an error.
func TestR188_ChunkIntegrityDetectsMixedChunks(t *testing.T) {
	cm := NewChunkManager(NewLogger(DefaultLogLevel))
	config := TokenConfig{
		Type:         "access",
		MinLength:    5,
		MaxLength:    100 * 1024,
		MaxChunks:    25,
		MaxChunkSize: maxCookieSize,
	}

	// Reassembled chunks form the opaque token "aaabbb"; but chunk 0's
	// stored integrity was computed over a DIFFERENT string (a stale chunk
	// from another session), so the set is mixed despite counts matching.
	chunks := map[int]*sessions.Session{
		0: {Values: map[interface{}]interface{}{
			"token_chunk":     "aaa",
			"token_total":     2,
			"chunk_integrity": fmt.Sprintf("%x", sha256.Sum256([]byte("different-set"))),
		}},
		1: {Values: map[interface{}]interface{}{
			"token_chunk": "bbb",
			"token_total": 2,
		}},
	}

	res := cm.GetToken("", false, chunks, config)
	if res.Error == nil {
		t.Fatalf("mixed chunk set must be rejected by chunk-integrity check; got token %q (old code returned it)", res.Token)
	}
}

// A consistent set with a matching integrity value must still assemble.
func TestR188_ChunkIntegrityValidSetStillSucceeds(t *testing.T) {
	cm := NewChunkManager(NewLogger(DefaultLogLevel))
	config := TokenConfig{
		Type:         "access",
		MinLength:    5,
		MaxLength:    100 * 1024,
		MaxChunks:    25,
		MaxChunkSize: maxCookieSize,
	}

	chunks := map[int]*sessions.Session{
		0: {Values: map[interface{}]interface{}{
			"token_chunk":     "aaa",
			"token_total":     2,
			"chunk_integrity": fmt.Sprintf("%x", sha256.Sum256([]byte("aaabbb"))),
		}},
		1: {Values: map[interface{}]interface{}{
			"token_chunk": "bbb",
			"token_total": 2,
		}},
	}

	res := cm.GetToken("", false, chunks, config)
	if res.Error != nil {
		t.Fatalf("valid coherent chunk set must assemble; got error: %v", res.Error)
	}
	if res.Token != "aaabbb" {
		t.Fatalf("expected reassembled token %q, got %q", "aaabbb", res.Token)
	}
}
