package traefikoidc

import "testing"

// FuzzParseJWTFuzz verifies parseJWT (used on attacker-controlled cookies /
// bearer tokens) never panics on arbitrary input — no slice OOB, no
// unbounded alloc, no JSON-engine surprise. It must return an error or a
// valid JWT, never panic (R193).
func FuzzParseJWTFuzz(f *testing.F) {
	seeds := []string{
		"",
		".",
		"a.b.c",
		"...",
		"eyJhbGciOiJSUzI1NiIsImtpZCI6ImsifQ.eyJzdWIiOiJ4In0.sig", // valid header+claims
		"$$$.$$$.$$$",
		"a\u202e.\nb.\t",
		"%%%",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = parseJWT(token) // must not panic
	})
}
