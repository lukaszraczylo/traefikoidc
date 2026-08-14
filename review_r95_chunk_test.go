package traefikoidc

import (
	"strings"
	"testing"

	"github.com/gorilla/sessions"
)

// TestChunkManagerReadsWhatWritePathAllows is an R95 regression for the
// write/read chunk-limit mismatch: the write path (session.go Set*Token)
// accepts up to 50 chunks, but the read path rejected any token with more
// than its per-type MaxChunks (access 25 / refresh 15 / id 20). A token
// needing e.g. 16 refresh chunks was therefore written yet permanently
// unreadable (data loss / forced re-auth). The read limits are now aligned
// to the write cap, so 16 refresh chunks must round-trip.
func TestChunkManagerReadsWhatWritePathAllows(t *testing.T) {
	cm := NewChunkManager(NewLogger("error"))

	const n = 16                             // unique refresh token only becomes readable after the R95 fix
	payload := strings.Repeat("abcdefgh", 8) // 64 chars, > MinLength
	parts := splitIntoChunks(payload, len(payload)/n)

	chunks := make(map[int]*sessions.Session, n)
	for i := 0; i < n; i++ {
		chunks[i] = &sessions.Session{Values: map[interface{}]interface{}{
			"token_chunk": parts[i],
			"token_total": n,
		}}
	}

	res := cm.processChunkedToken(chunks, RefreshTokenConfig)
	if res.Error != nil {
		if strings.Contains(res.Error.Error(), "too many") || strings.Contains(res.Error.Error(), "max") {
			t.Fatalf("written token is unreadable: %v", res.Error)
		}
		// Other validation error would be a different (legit) concern; fail
		// hard so the round-trip guarantee is explicit.
		t.Fatalf("unexpected reassembly error: %v", res.Error)
	}
	if res.Token != payload {
		t.Fatalf("round-trip mismatch: got %q, want %q", res.Token, payload)
	}
}
