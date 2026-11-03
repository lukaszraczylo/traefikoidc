package traefikoidc

import (
	"testing"

	"github.com/gorilla/sessions"
)

// invalidationInputs must return exactly what extractSessionInfo and
// sessionCreatedAtForInvalidation return when called separately.
func TestInvalidationInputsMatchSeparateCalls(t *testing.T) {
	oidc := &TraefikOidc{logger: newNoOpLogger()}
	sess := &SessionData{mainSession: &sessions.Session{Values: map[interface{}]interface{}{"created_at": int64(1700000000)}}}

	tokens := map[string]string{
		"all claims":  makeTestJWT(t, map[string]interface{}{"sid": "s1", "sub": "u1", "iat": float64(1700000100)}),
		"no iat":      makeTestJWT(t, map[string]interface{}{"sid": "s1", "sub": "u1"}),
		"sid only":    makeTestJWT(t, map[string]interface{}{"sid": "s1", "iat": float64(1700000200)}),
		"sub only":    makeTestJWT(t, map[string]interface{}{"sub": "u1"}),
		"wrong types": makeTestJWT(t, map[string]interface{}{"sid": 5, "sub": true, "iat": "x"}),
		"malformed":   "not-a-jwt",
		"empty":       "",
	}
	for name, tok := range tokens {
		t.Run(name, func(t *testing.T) {
			wantSID, wantSub, _ := oidc.extractSessionInfo(tok)
			wantAt := oidc.sessionCreatedAtForInvalidation(tok, sess)
			gotSID, gotSub, gotAt := oidc.invalidationInputs(tok, sess)
			if gotSID != wantSID || gotSub != wantSub || !gotAt.Equal(wantAt) {
				t.Fatalf("got (%q,%q,%v) want (%q,%q,%v)", gotSID, gotSub, gotAt, wantSID, wantSub, wantAt)
			}
		})
	}
}
