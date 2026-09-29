package traefikoidc

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestIDTokenMemoFollowsStoredToken(t *testing.T) {
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef", false, "", "", time.Hour, NewLogger("error"))
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	t.Cleanup(func() {
		if err := sm.Shutdown(); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	future := float64(time.Now().Add(time.Hour).Unix())
	first := tokenWithGroups(t, map[string]interface{}{"sub": "first", "exp": future})
	second := tokenWithGroups(t, map[string]interface{}{"sub": "second", "exp": future})

	session, err := sm.GetSession(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	steps := []struct {
		name  string
		write func()
		want  string
	}{
		{"first read", func() { session.SetIDToken(first) }, first},
		{"repeat read", func() {}, first},
		{"after overwrite", func() { session.SetIDToken(second) }, second},
		{"after clearing", func() { session.SetIDToken("") }, ""},
		{"after Reset", func() { session.SetIDToken(first); _ = session.GetIDToken(); session.Reset() }, ""},
	}
	for _, st := range steps {
		st.write()
		if got := session.GetIDToken(); got != st.want {
			t.Fatalf("%s: GetIDToken = %q, want %q", st.name, got, st.want)
		}
		if st.name == "repeat read" && session.idTokenMemoRaw != first {
			t.Fatal("repeat read did not go through the memo; the test no longer covers it")
		}
	}
	if session.idTokenMemoRaw != "" || session.idTokenMemo != "" {
		t.Fatal("Reset left an ID-token memo on the pooled session")
	}
}
