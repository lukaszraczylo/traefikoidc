package traefikoidc

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lukaszraczylo/traefikoidc/internal/utils"
)

// A deep link longer than the cap must not be persisted into the cookies.
func TestSetIncomingPathCapsLength(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, NewLogger("error"))
	if err != nil {
		t.Fatal(err)
	}
	sess, err := sm.GetSession(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.returnToPoolSafely)

	sess.SetIncomingPath("/ok?a=1")
	if got := sess.GetIncomingPath(); got != "/ok?a=1" {
		t.Fatalf("short path changed: %q", got)
	}
	sess.SetIncomingPath("/x?" + strings.Repeat("q", maxIncomingPathLen+1))
	if got := sess.GetIncomingPath(); got != "" {
		t.Fatalf("oversized path stored (%d bytes)", len(got))
	}
}

func TestDetermineSchemeCaseInsensitive(t *testing.T) {
	for in, want := range map[string]string{"HTTPS": "https", "Https": "https", "HTTP": "http", "https": "https"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("X-Forwarded-Proto", in)
		if got := utils.DetermineScheme(r, false); got != want {
			t.Errorf("X-Forwarded-Proto %q -> %q, want %q", in, got, want)
		}
	}
}
