package traefikoidc

import (
	"net/http"
	"testing"
	"text/template"
	"time"
)

// newTestOIDC builds a *TraefikOidc ready for ServeHTTP-level tests, with
// the baseline fields nearly every hand-built &TraefikOidc{} literal in this
// package repeats: a next handler that answers 200, an error-level logger,
// a closed initComplete gate, a real session manager, both startup
// barriers past their "not yet initialized" state, and a plausible
// issuer/callback/client. Pass opts to set or override any field -
// TraefikOidc's fields are unexported, so an opt is a func(*TraefikOidc)
// written in a _test.go file in this package (same-package test files can
// set unexported fields directly).
//
// Introduced for FIX-41: 71 files hand-build this literal (112 times
// total), so a change to TraefikOidc's required fields must be patched in
// dozens of places. New tests should prefer this builder; existing round
// files are being folded onto it incrementally, keeping the R-number in
// each test's comment.
func newTestOIDC(t *testing.T, opts ...func(*TraefikOidc)) *TraefikOidc {
	t.Helper()
	oidc := &TraefikOidc{
		next:                         http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		logger:                       NewLogger("error"),
		initComplete:                 make(chan struct{}),
		sessionManager:               createTestSessionManager(t),
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
		issuerURL:                    "https://provider.example.com",
		redirURLPath:                 "/callback",
		clientID:                     "test-client",
	}
	close(oidc.initComplete)
	for _, opt := range opts {
		opt(oidc)
	}
	return oidc
}

// stubIntrospectionCache is a minimal introspectionCacheInterface stub that
// always returns the same canned *IntrospectionResponse (or a miss when v
// is nil). Moved here from review_r126_test.go (FIX-41): review_r143_test.go
// and review_r149_test.go also use it, so a helper declared inside one
// round file was a hidden cross-file dependency - deleting or renaming
// review_r126_test.go would have broken both.
type stubIntrospectionCache struct{ v *IntrospectionResponse }

func (s *stubIntrospectionCache) Set(key string, value any, ttl time.Duration) {}
func (s *stubIntrospectionCache) Get(key string) (any, bool) {
	if s.v != nil {
		return s.v, true
	}
	return nil, false
}
func (s *stubIntrospectionCache) Delete(key string)        {}
func (s *stubIntrospectionCache) SetMaxSize(size int)      {}
func (s *stubIntrospectionCache) Size() int                { return 0 }
func (s *stubIntrospectionCache) Clear()                   {}
func (s *stubIntrospectionCache) Cleanup()                 {}
func (s *stubIntrospectionCache) Close()                   {}
func (s *stubIntrospectionCache) GetStats() map[string]any { return nil }

// mustTemplate parses src as a header template or panics. Moved here from
// review_r73_test.go (FIX-41): review_r103_test.go also uses it, so a
// helper declared inside one round file was a hidden cross-file
// dependency - deleting or renaming review_r73_test.go would have broken
// review_r103_test.go.
func mustTemplate(src string) *template.Template {
	tmpl, err := template.New("h").Parse(src)
	if err != nil {
		panic(err)
	}
	return tmpl
}
