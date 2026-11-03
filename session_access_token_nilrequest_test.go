package traefikoidc

import (
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"testing"
)

// A chunked store that cannot run (no request to bind chunk cookies to) must
// leave the previous access token intact.
func TestSetAccessTokenNilRequestKeepsOldToken(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, NewLogger("error"))
	if err != nil {
		t.Fatal(err)
	}
	sess, err := sm.GetSession(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.returnToPoolSafely)

	const old = "smallaccesstokenvaluevaluevalue"
	sess.SetAccessToken(old)

	blob := make([]byte, 3000)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	sess.request = nil
	sess.SetAccessToken(base64.StdEncoding.EncodeToString(blob))

	if got := sess.GetAccessToken(); got != old {
		t.Fatalf("old access token lost after a failed chunked store: %q", got)
	}
}
