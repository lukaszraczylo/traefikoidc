package traefikoidc

import (
	"testing"
	"time"
)

// FIX-03 regression tests.
//
// R159 sent every opaque (non-JWT) bearer token to
// buildPrincipalFromOpaqueIntrospection whenever requireTokenIntrospection
// was enabled, with none of the JWT-path gates: allowOpaqueTokens was never
// checked, the introspected client_id/audience was never bound to this
// client when the operator left audience==clientID (the common default),
// and IdP-initiated logout (isSessionInvalidated) was never consulted. Any
// introspected active=true token from the same IdP therefore authenticated,
// including one issued to a completely different client.

// TestBearerOpaqueIntrospection_RequiresAllowOpaqueTokens guards the
// allowOpaqueTokens gate: with it left at its default (false), an opaque
// bearer token must be rejected even when requireTokenIntrospection is on
// and the introspection endpoint reports the token active.
func TestBearerOpaqueIntrospection_RequiresAllowOpaqueTokens(t *testing.T) {
	active := &IntrospectionResponse{Active: true, Sub: "user-1", ClientID: "my-client"}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: active},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         false, // default
		clientID:                  "my-client",
	}
	_, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr == nil {
		t.Fatal("opaque bearer token must be rejected when allowOpaqueTokens is false, even with requireTokenIntrospection on")
	}
}

// TestBearerOpaqueIntrospection_RejectsForeignClient guards the client
// binding: when audience==clientID (no distinct API audience configured),
// an introspected token whose client_id names another client, and whose
// aud does not contain this client either, must be rejected.
func TestBearerOpaqueIntrospection_RejectsForeignClient(t *testing.T) {
	foreign := &IntrospectionResponse{Active: true, Sub: "user-1", ClientID: "other-client"}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: foreign},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
	}
	_, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr == nil {
		t.Fatal("an introspected token issued to a different client_id must be rejected")
	}
}

// TestBearerOpaqueIntrospection_AcceptsOwnClientViaClientID is the positive
// control: client_id matching this client must still authenticate.
func TestBearerOpaqueIntrospection_AcceptsOwnClientViaClientID(t *testing.T) {
	own := &IntrospectionResponse{Active: true, Sub: "user-1", ClientID: "my-client"}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: own},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
	}
	p, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr != nil {
		t.Fatalf("a token issued to this client_id must be accepted, got: %v", bErr)
	}
	if p.Identifier != "user-1" {
		t.Fatalf("expected identifier %q, got %q", "user-1", p.Identifier)
	}
}

// TestBearerOpaqueIntrospection_AcceptsOwnClientViaAud is the positive
// control for providers that omit client_id from the introspection
// response but carry it in aud instead (RFC 7662 leaves client_id
// optional).
func TestBearerOpaqueIntrospection_AcceptsOwnClientViaAud(t *testing.T) {
	own := &IntrospectionResponse{Active: true, Sub: "user-1", Aud: "my-client"}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: own},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
	}
	_, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr != nil {
		t.Fatalf("a token whose aud contains this client_id must be accepted, got: %v", bErr)
	}
}

// TestBearerOpaqueIntrospection_InvalidatedSessionRejected guards the
// IdP-initiated-logout check: a subject invalidated via backchannel logout
// must be rejected even though the introspected token itself reports
// active=true. The introspection response carries no sid (RFC 7662 does
// not define one), so this checks invalidation by sub, mirroring the JWT
// bearer path's isSessionInvalidated(sid, sub, createdAt) call with an
// empty sid.
func TestBearerOpaqueIntrospection_InvalidatedSessionRejected(t *testing.T) {
	cache := NewCache()
	defer cache.Close()

	own := &IntrospectionResponse{Active: true, Sub: "user-1", ClientID: "my-client"}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: own},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
		sessionInvalidationCache:  cache,
	}
	if err := tObj.invalidateSession("", "user-1"); err != nil {
		t.Fatalf("invalidateSession: %v", err)
	}

	_, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr == nil {
		t.Fatal("an introspected token for a subject invalidated by backchannel logout must be rejected")
	}
}

// TestBearerOpaqueIntrospection_NotYetInvalidatedAccepted is the positive
// control: a subject with no invalidation entry must still authenticate.
func TestBearerOpaqueIntrospection_NotYetInvalidatedAccepted(t *testing.T) {
	cache := NewCache()
	defer cache.Close()

	own := &IntrospectionResponse{Active: true, Sub: "user-1", ClientID: "my-client"}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: own},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
		sessionInvalidationCache:  cache,
	}
	_, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr != nil {
		t.Fatalf("a subject with no invalidation entry must authenticate, got: %v", bErr)
	}
}

// TestBearerOpaqueIntrospection_UsesBearerIdentifierClaim guards that the
// identifier is resolved through bearerIdentifierClaim + sanitizeBearerIdentifier
// like the JWT bearer path, instead of always preferring sub.
func TestBearerOpaqueIntrospection_UsesBearerIdentifierClaim(t *testing.T) {
	own := &IntrospectionResponse{Active: true, Sub: "user-1", Username: "svc-account", ClientID: "my-client"}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: own},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
		bearerIdentifierClaim:     "username",
	}
	p, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr != nil {
		t.Fatalf("unexpected error: %v", bErr)
	}
	if p.Identifier != "svc-account" {
		t.Fatalf("expected identifier from configured claim %q, got %q", "username", p.Identifier)
	}
}

// TestBearerOpaqueIntrospection_MaxTokenAgeEnforced guards that maxTokenAge
// bounds the introspected token's iat like enforceIatAge does for the JWT
// path, when the AS returns one.
func TestBearerOpaqueIntrospection_MaxTokenAgeEnforced(t *testing.T) {
	stale := &IntrospectionResponse{
		Active:   true,
		Sub:      "user-1",
		ClientID: "my-client",
		Iat:      time.Now().Add(-2 * time.Hour).Unix(),
	}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: stale},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
		maxTokenAge:               time.Hour,
	}
	_, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr == nil {
		t.Fatal("an introspected token whose iat is older than maxTokenAge must be rejected")
	}
}
