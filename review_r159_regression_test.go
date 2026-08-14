package traefikoidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// serializingCache simulates a UniversalCache backed by a serializing
// store (e.g. Redis): Set JSON-round-trips the value, so Get returns a
// generic map, never the original concrete type. This is exactly what
// production sees on the distributed path.
type serializingCache struct {
	m map[string]interface{}
}

func (c *serializingCache) Set(key string, value any, ttl time.Duration) {
	b, _ := json.Marshal(value)
	var v interface{}
	_ = json.Unmarshal(b, &v)
	c.m[key] = v
}
func (c *serializingCache) Get(key string) (any, bool) {
	v, ok := c.m[key]
	return v, ok
}
func (c *serializingCache) Delete(key string)        { delete(c.m, key) }
func (c *serializingCache) SetMaxSize(int)           {}
func (c *serializingCache) Size() int                { return len(c.m) }
func (c *serializingCache) Clear()                   { c.m = map[string]interface{}{} }
func (c *serializingCache) Cleanup()                 {}
func (c *serializingCache) Close()                   {}
func (c *serializingCache) GetStats() map[string]any { return nil }

// TestR159_RefreshResultDedupAcrossSerializingCache guards the
// lookupCachedRefreshResult cross-backend decode (token_manager.go). The
// refresh-result dedup stored a *TokenResponse but the serializing
// backend returns it as a JSON map, so the *TokenResponse type-assert
// always failed and every replica still posted the refresh token — the
// advertised cross-replica grant coalescing was silently inert. The fix
// normalizes serialized forms back to *TokenResponse.
// Fail-on-old: lookup returns nil/false on a serializing backend.
func TestR159_RefreshResultDedupAcrossSerializingCache(t *testing.T) {
	tObj := &TraefikOidc{
		refreshResultCache: &serializingCache{m: map[string]interface{}{}},
	}

	tObj.cacheRefreshResult("session-1", &TokenResponse{
		AccessToken:  "at-1",
		RefreshToken: "rt-rotated",
	})

	tr, ok := tObj.lookupCachedRefreshResult("session-1")
	if !ok || tr == nil {
		t.Fatal("refresh result dedup must survive a serializing backend; lookup returned nothing")
	}
	if tr.AccessToken != "at-1" || tr.RefreshToken != "rt-rotated" {
		t.Fatalf("dedup round-trip corrupted the token; got %+v", tr)
	}
}

// TestR159_BearerOpaqueTokenIntrospectedWhenRequired guards the bearer
// opaque-token path (bearer_auth.go). The JWT-shape gate
// (strings.Count(token,'.') != 2) ran before the introspection branch,
// so every opaque bearer access token got a 401 even when
// requireTokenIntrospection was enabled for exactly that purpose. The fix
// introspects opaque tokens on the bearer path (mirroring the session
// path's validateOpaqueToken) and forwards with the introspected
// subject.
// Fail-on-old: opaque token rejected (401) despite active introspection.
func TestR159_BearerOpaqueTokenIntrospectedWhenRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active":     true,
			"sub":        "opaque-user",
			"token_type": "Bearer",
		})
	}))
	defer ts.Close()

	var nextCalled atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	})

	oidc := makeBearerOIDC(t, next)
	oidc.requireTokenIntrospection = true
	oidc.introspectionURL = ts.URL
	oidc.httpClient = ts.Client()
	oidc.clientSecret = "secret"

	req := httptest.NewRequest("GET", "/api/x", nil)
	req.Header.Set("Authorization", "Bearer opaque-token-with-no-dots")
	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, req)

	if !nextCalled.Load() {
		t.Fatalf("opaque token must be introspected and forwarded when requireTokenIntrospection is set; status=%d body=%q", rw.Code, rw.Body.String())
	}
}
