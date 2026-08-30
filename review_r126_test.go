package traefikoidc

import (
	"testing"
	"time"
)

// TestDetectTokenType_MultiAudienceIDToken guards the R126 fix to
// token_manager.go detectTokenType: an ID token whose `aud` is an array
// with client_id as one of several entries (common in multi-audience
// setups, e.g. [clientID, API-resource]) was previously classified as an
// access token because of a `len(audArr) == 1` guard. It was then
// validated against the broader configured `audience` instead of
// clientID, rejecting valid logins. client_id present anywhere in the
// array means ID token.
func TestDetectTokenType_MultiAudienceIDToken(t *testing.T) {
	tObj := &TraefikOidc{clientID: "client-abc"}
	jwt := &JWT{Claims: map[string]interface{}{
		"aud": []interface{}{"client-abc", "api:resource"},
	}}
	if !tObj.detectTokenType(jwt, "raw.token") {
		t.Fatal("multi-audience token containing client_id must be classified as an ID token")
	}
}

// TestJWTVerify_IatOptional guards the R126 fix to jwt.go JWT.Verify:
// `iat` is OPTIONAL per RFC 7519 §4.1.6, but Verify hard-required it.
// Because Verify is also reached for access and logout tokens, a valid
// token whose provider omits iat was rejected. Verify must validate iat
// only when present.
func TestJWTVerify_IatOptional(t *testing.T) {
	jwt := &JWT{
		Header: map[string]interface{}{"alg": "RS256"},
		Claims: map[string]interface{}{
			"iss": "https://issuer.example.com",
			"aud": "client-abc",
			"exp": float64(time.Now().Add(time.Hour).Unix()),
			"sub": "user-1",
			// intentionally no "iat"
		},
	}
	if err := jwt.Verify("https://issuer.example.com", "client-abc", true); err != nil {
		t.Fatalf("token without optional iat claim must verify, got: %v", err)
	}
}

// TestBearerIntrospection_ExpiredActiveRejected guards the R126 fix to
// bearer_auth.go introspectOnBearerPath: the bearer path checked only
// resp.Active, while the equivalent session path (validateOpaqueToken)
// also rejects an already-expired exp. A provider returning active=1 with
// an expired exp could therefore let the token pass on the bearer path
// while the identical token was rejected on the session path. The bearer
// path must apply the same expiration check.
func TestBearerIntrospection_ExpiredActiveRejected(t *testing.T) {
	expired := &IntrospectionResponse{Active: true, Exp: time.Now().Add(-time.Hour).Unix()}
	tObj := &TraefikOidc{introspectionCache: &stubIntrospectionCache{v: expired}, logger: NewLogger("debug")}
	if bErr := tObj.introspectOnBearerPath("tok"); bErr == nil {
		t.Fatal("an active-but-already-expired introspection result must be rejected on the bearer path")
	}
}

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
