package traefikoidc

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"testing"
)

// TestR170_PreservesChunkedOldAccessTokenOnNewTooLarge regresses a gap in the
// R122 fix to SetAccessToken (session.go): R122 covered the case where the
// PREVIOUS access token was stored inline (accessSession.Values["token"]),
// but NOT the case where the previous token was itself large enough to be
// stored as CHUNKS (sd.accessTokenChunks). The early
//
//	for k := range sd.accessTokenChunks { delete }
//
// still ran before the new token's chunk validation, so when a new token's
// compressed size lands in the (70KB, 100KB] band (splitIntoChunks yields
// >50 chunks at maxCookieSize=1400) the write aborts after already wiping
// the previous chunked access token — the user keeps a session whose valid
// access token is gone, forcing an unnecessary re-authentication.
func TestR170_PreservesChunkedOldAccessTokenOnNewTooLarge(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, NewLogger("error"))
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	sess, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	t.Cleanup(sess.returnToPoolSafely)

	// A previous access token large enough to be stored as chunks (> maxCookieSize)
	// but under the 50-chunk cap: ~30KB of incompressible data.
	oldRaw := make([]byte, 30*1024)
	if _, err := cryptorand.Read(oldRaw); err != nil {
		t.Fatal(err)
	}
	oldToken := base64.StdEncoding.EncodeToString(oldRaw)

	sess.SetAccessToken(oldToken)
	if got := sess.GetAccessToken(); got != oldToken {
		t.Fatalf("precondition: chunked old token must be retrievable, got len %d (want %d)", len(got), len(oldToken))
	}
	if len(sess.accessTokenChunks) == 0 {
		t.Fatal("precondition: old access token should be stored as chunks")
	}

	// A new incompressible token whose compressed size lands between
	// 50*maxCookieSize (70KB) and the 100KB cap, so the chunked branch
	// splits into >50 chunks and aborts after too-many-chunks.
	newRaw := make([]byte, 60*1024)
	if _, err := cryptorand.Read(newRaw); err != nil {
		t.Fatal(err)
	}
	bigToken := base64.StdEncoding.EncodeToString(newRaw)

	sess.SetAccessToken(bigToken)

	if got := sess.GetAccessToken(); got != oldToken {
		t.Fatalf("previous chunked access token must be preserved when storing a new oversized token fails, got len %d (want %d)", len(got), len(oldToken))
	}
}
