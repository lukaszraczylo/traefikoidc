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

// TestBearerOpaqueIntrospection_MissingIatRejectedWithMaxTokenAge guards
// that an opaque token whose introspection response carries no iat is
// bound by maxTokenAge exactly like enforceIatAge binds the JWT path: when
// maxTokenAge > 0 (New() always sets it so — 0/unset becomes 24h,
// main.go's config-default closure), a missing iat gives nothing to bound
// the token's age against, so it must fail closed rather than bypass the
// age check entirely.
func TestBearerOpaqueIntrospection_MissingIatRejectedWithMaxTokenAge(t *testing.T) {
	noIat := &IntrospectionResponse{Active: true, Sub: "user-1", ClientID: "my-client"} // Iat left zero
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: noIat},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
		maxTokenAge:               24 * time.Hour,
	}
	_, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr == nil {
		t.Fatal("an introspected opaque token with no iat must be rejected when maxTokenAge is set, matching enforceIatAge's fail-closed contract on the JWT path")
	}
}

// TestBearerOpaqueIntrospection_SidOnlyLogoutRejected guards front-channel
// (sid-only) logout reaching an opaque bearer token. isSessionInvalidated
// used to be called with a hardcoded empty sid, so a logout recorded only
// by sid (front-channel logout always records this way; so does a
// back-channel logout token carrying only sid) never revoked an opaque
// token even when the introspection response itself carried a sid.
func TestBearerOpaqueIntrospection_SidOnlyLogoutRejected(t *testing.T) {
	cache := NewCache()
	defer cache.Close()

	withSid := &IntrospectionResponse{Active: true, Sub: "user-1", ClientID: "my-client", Sid: "session-1"}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: withSid},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
		sessionInvalidationCache:  cache,
	}
	if err := tObj.invalidateSession("session-1", ""); err != nil {
		t.Fatalf("invalidateSession: %v", err)
	}

	_, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr == nil {
		t.Fatal("an introspected token whose sid was invalidated by a sid-only (front-channel) logout must be rejected, when the introspection response carries that sid")
	}
}

// TestBearerOpaqueIntrospection_RevokedTokenRejected guards the local
// revocation blacklist: the JWT bearer path rejects a raw token that
// RevokeToken blacklisted (verifyTokenWithOpts, token_manager.go:71-75), and
// handleLogout calls RevokeToken on the session's access token specifically
// so "a token captured before logout ... cannot be reused" (helpers.go).
// buildPrincipalFromOpaqueIntrospection never consulted t.tokenBlacklist, so
// a captured opaque bearer token kept authenticating as the victim after
// logout for as long as the IdP still reported it active.
func TestBearerOpaqueIntrospection_RevokedTokenRejected(t *testing.T) {
	blacklist := NewCache()
	defer blacklist.Close()

	active := &IntrospectionResponse{Active: true, Sub: "victim", ClientID: "my-client"}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: active},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
		tokenBlacklist:            blacklist,
		tokenCache:                NewTokenCache(),
	}
	defer tObj.tokenCache.Close()

	const token = "opaque-victim-token"
	tObj.RevokeToken(token)

	_, bErr := tObj.buildPrincipalFromOpaqueIntrospection(token)
	if bErr == nil {
		t.Fatal("an opaque bearer token blacklisted by RevokeToken (logout) must be rejected, even though introspection still reports it active")
	}
	if bErr.kind != bearerErrTokenInactive {
		t.Fatalf("want bearerErrTokenInactive (401), got kind %v", bErr.kind)
	}
}

// TestBearerOpaqueIntrospection_BlacklistedJtiRejected guards the jti side
// of the same gate: when the introspection response carries a jti and that
// jti is blacklisted (e.g. the IdP echoes the same jti it minted for a JWT
// RevokeToken already blacklisted by jti), the opaque path must reject it
// too, unless disableReplayDetection is set — mirroring the JWT path's
// tokenCache-hit jti check (token_manager.go:90-96).
func TestBearerOpaqueIntrospection_BlacklistedJtiRejected(t *testing.T) {
	blacklist := NewCache()
	defer blacklist.Close()
	blacklist.Set("revoked-jti-1", true, time.Hour)

	withJti := &IntrospectionResponse{Active: true, Sub: "victim", ClientID: "my-client", Jti: "revoked-jti-1"}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: withJti},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
		tokenBlacklist:            blacklist,
	}

	_, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr == nil {
		t.Fatal("an opaque bearer token whose introspection jti is blacklisted must be rejected")
	}
	if bErr.kind != bearerErrTokenInactive {
		t.Fatalf("want bearerErrTokenInactive (401), got kind %v", bErr.kind)
	}
}

// TestBearerOpaqueIntrospection_NbfFutureRejected guards the not-before
// check the JWT path applies through verifyTimeClaims and the session path
// applies through validateOpaqueToken (token_introspection.go:258-263): an
// introspection response reporting a future nbf must be rejected on the
// bearer path too.
func TestBearerOpaqueIntrospection_NbfFutureRejected(t *testing.T) {
	notYetValid := &IntrospectionResponse{
		Active:   true,
		Sub:      "user-1",
		ClientID: "my-client",
		Nbf:      time.Now().Add(time.Hour).Unix(),
	}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: notYetValid},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
	}
	_, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr == nil {
		t.Fatal("an introspected token with nbf in the future must be rejected")
	}
	if bErr.kind != bearerErrTokenInactive {
		t.Fatalf("want bearerErrTokenInactive (401), got kind %v", bErr.kind)
	}
}

// TestBearerOpaqueIntrospection_UsesClientIDClaim guards that
// bearerIdentifierClaim can resolve against any IntrospectionResponse
// member, not just sub/username — client_id, scope, iss, jti and aud must
// all be available too.
func TestBearerOpaqueIntrospection_UsesClientIDClaim(t *testing.T) {
	own := &IntrospectionResponse{Active: true, Sub: "user-1", ClientID: "my-client"}
	tObj := &TraefikOidc{
		logger:                    newNoOpLogger(),
		introspectionCache:        &stubIntrospectionCache{v: own},
		requireTokenIntrospection: true,
		allowOpaqueTokens:         true,
		clientID:                  "my-client",
		bearerIdentifierClaim:     "client_id",
	}
	p, bErr := tObj.buildPrincipalFromOpaqueIntrospection("opaque-token")
	if bErr != nil {
		t.Fatalf("unexpected error: %v", bErr)
	}
	if p.Identifier != "my-client" {
		t.Fatalf("expected identifier from configured claim %q, got %q", "client_id", p.Identifier)
	}
}
