package traefikoidc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// signGraphStyleAccessToken builds a JWT in Microsoft's Graph proprietary
// nonce-header form: bytes that get signed contain the SHA256 hash of the
// nonce, while the wire token ships the original nonce. A standard JWS
// verifier always rejects these with `crypto/rsa: verification error`, which
// is why Microsoft documents Graph access tokens as opaque to client apps:
//
//	https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
//	"you can't validate tokens for Microsoft Graph according to these rules
//	 due to their proprietary format"
func signGraphStyleAccessToken(t *testing.T, key *rsa.PrivateKey, kid, originalNonce string, claims map[string]any) string {
	t.Helper()

	wireHeader := map[string]any{
		"alg":   "RS256",
		"kid":   kid,
		"typ":   "JWT",
		"nonce": originalNonce,
	}
	wireHeaderJSON, err := json.Marshal(wireHeader)
	require.NoError(t, err)

	hashed := sha256.Sum256([]byte(originalNonce))
	signedHeader := map[string]any{
		"alg":   "RS256",
		"kid":   kid,
		"typ":   "JWT",
		"nonce": fmt.Sprintf("%x", hashed),
	}
	signedHeaderJSON, err := json.Marshal(signedHeader)
	require.NoError(t, err)

	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	wireHeaderB64 := base64.RawURLEncoding.EncodeToString(wireHeaderJSON)
	signedHeaderB64 := base64.RawURLEncoding.EncodeToString(signedHeaderJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signedInput := signedHeaderB64 + "." + claimsB64
	hSign := sha256.Sum256([]byte(signedInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hSign[:])
	require.NoError(t, err)

	return wireHeaderB64 + "." + claimsB64 + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// newAzureFollowupOIDC produces a TraefikOidc instance wired for an Azure
// AD tenant with a captured error log buffer. Used by the issue #134 followup
// tests to assert log behavior during validateAzureTokens flows.
func newAzureFollowupOIDC(t *testing.T, jwks *JWKSet) (*TraefikOidc, *bytes.Buffer) {
	t.Helper()
	tc := newTestCleanup(t)

	errBuf := &bytes.Buffer{}
	logger := &Logger{
		logError: log.New(errBuf, "", 0),
		logInfo:  log.New(io.Discard, "", 0),
		logDebug: log.New(io.Discard, "", 0),
	}

	tokenCache := tc.addTokenCache(NewTokenCache())
	tokenBlacklist := tc.addCache(NewCache())

	oidc := &TraefikOidc{
		issuerURL:         "https://login.microsoftonline.com/tenant-id/v2.0",
		clientID:          "test-client-id",
		audience:          "test-client-id",
		jwksURL:           "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys",
		limiter:           rate.NewLimiter(rate.Every(time.Second), 100),
		logger:            logger,
		httpClient:        &http.Client{Timeout: 10 * time.Second},
		jwkCache:          &MockJWKCache{JWKS: jwks},
		tokenCache:        tokenCache,
		tokenBlacklist:    tokenBlacklist,
		extractClaimsFunc: extractClaims,
	}
	oidc.tokenVerifier = oidc
	oidc.jwtVerifier = oidc
	require.True(t, oidc.isAzureProvider(), "fixture must be detected as Azure provider")
	return oidc, errBuf
}

// authedSessionWithTokens returns a SessionData populated with the supplied
// access and ID tokens, marked authenticated and recently created. The
// SessionManager carries a real ChunkManager so that GetAccessToken /
// GetIDToken / GetRefreshToken behave like the production code path.
func authedSessionWithTokens(t *testing.T, accessToken, idToken string) *SessionData {
	t.Helper()

	chunkLogger := NewLogger("error")
	chunkManager := NewChunkManager(chunkLogger)
	t.Cleanup(chunkManager.Shutdown)

	sd := CreateMockSessionData()
	sd.manager = &SessionManager{
		sessionMaxAge: 24 * time.Hour,
		chunkManager:  chunkManager,
		logger:        chunkLogger,
	}

	sd.mainSession = sessions.NewSession(nil, "main")
	sd.mainSession.Values["authenticated"] = true
	sd.mainSession.Values["created_at"] = time.Now().Unix()

	sd.accessSession = sessions.NewSession(nil, "access")
	sd.accessSession.Values["token"] = accessToken
	sd.accessSession.Values["compressed"] = false

	sd.idTokenSession = sessions.NewSession(nil, "id")
	sd.idTokenSession.Values["token"] = idToken
	sd.idTokenSession.Values["compressed"] = false

	sd.refreshSession = sessions.NewSession(nil, "refresh")
	sd.refreshSession.Values["token"] = ""
	sd.refreshSession.Values["compressed"] = false

	return sd
}

// TestIssue134_Followup_GraphAccessTokenReproducesUsersError sanity-checks
// that our crafted Graph-style token reproduces the exact rsa error string
// quoted on the issue thread (dada-engineer 2026-05-08, friek 2026-05-11).
//
// Sanity test: must always pass, regardless of the issue #134 followup fix.
// It exists so a future contributor does not accidentally weaken the
// reproducer and assume the followup fix is no longer needed.
func TestIssue134_Followup_GraphAccessTokenReproducesUsersError(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const kid = "azure-followup-kid"
	graphToken := signGraphStyleAccessToken(t, rsaKey, kid, "wire-only-nonce", map[string]any{
		"iss": "https://login.microsoftonline.com/tenant-id/v2.0",
		"aud": "00000003-0000-0000-c000-000000000000",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"sub": "user-azure-id",
		"scp": "User.Read",
	})

	parsedJWT, err := parseJWT(graphToken)
	require.NoError(t, err)
	pubKey := &rsaKey.PublicKey
	alg, _ := parsedJWT.Header["alg"].(string)
	verifyErr := verifySignatureWithKey(graphToken, pubKey, alg)
	require.Error(t, verifyErr)
	assert.Contains(t, verifyErr.Error(), "crypto/rsa: verification error",
		"reproducer must emit the exact error string reported on issue #134")
}

// TestIssue134_Followup_ValidateAzureTokensSkipsGraphAccessToken is the
// failing-then-passing test for the followup fix.
//
// Symptom (before fix): validateAzureTokens calls verifyToken on every
// JWT-shaped access token. For Microsoft Graph access tokens (the default
// when no custom resource is registered), verification always fails with
// `crypto/rsa: verification error`, generating two error log lines per
// request:
//
//	UNKNOWN token verification failed: signature verification failed:
//	  crypto/rsa: verification error
//	DIAGNOSTIC: Signature verification failed for kid=<kid>, alg=RS256:
//	  crypto/rsa: verification error
//
// Microsoft's own documentation tells client apps not to validate Graph
// access tokens. The fix matches that guidance: when an Azure access token
// carries Microsoft's proprietary `nonce` JWT header, treat it as opaque
// (skip JWT verification, fall through to ID token validation).
func TestIssue134_Followup_ValidateAzureTokensSkipsGraphAccessToken(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const kid = "azure-followup-kid"
	jwk := JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}
	jwks := &JWKSet{Keys: []JWK{jwk}}

	now := time.Now()
	exp := now.Add(time.Hour).Unix()

	graphAccessToken := signGraphStyleAccessToken(t, rsaKey, kid, "wire-only-nonce-azure-graph", map[string]any{
		"iss":   "https://login.microsoftonline.com/tenant-id/v2.0",
		"aud":   "00000003-0000-0000-c000-000000000000",
		"exp":   exp,
		"iat":   now.Unix(),
		"sub":   "user-azure-id",
		"appid": "test-client-id",
		"scp":   "User.Read",
	})

	idToken, err := createTestJWT(rsaKey, "RS256", kid, map[string]any{
		"iss":   "https://login.microsoftonline.com/tenant-id/v2.0",
		"aud":   "test-client-id",
		"exp":   exp,
		"iat":   now.Add(-2 * time.Minute).Unix(),
		"nbf":   now.Add(-2 * time.Minute).Unix(),
		"sub":   "user-azure-id",
		"email": "user@example.com",
		"nonce": "id-token-oidc-nonce",
		"jti":   "id-token-jti-followup",
	})
	require.NoError(t, err)

	oidc, errBuf := newAzureFollowupOIDC(t, jwks)
	session := authedSessionWithTokens(t, graphAccessToken, idToken)

	authenticated, needsRefresh, expired := oidc.validateAzureTokens(session)

	output := errBuf.String()
	assert.NotContains(t, output, "crypto/rsa: verification error",
		"validateAzureTokens must not log rsa verification error for Graph-style access tokens; got: %q", output)
	assert.NotContains(t, output, "DIAGNOSTIC: Signature verification failed",
		"DIAGNOSTIC line must not fire for Graph-style access tokens; got: %q", output)
	assert.NotContains(t, output, "UNKNOWN token verification failed",
		"UNKNOWN classification log must not fire for Graph-style access tokens; got: %q", output)

	assert.True(t, authenticated, "session must remain authenticated via the ID token fallback")
	assert.False(t, needsRefresh, "valid ID token must not signal a refresh need")
	assert.False(t, expired, "valid ID token must not be reported as expired")
}

// TestIssue134_Followup_IsUnverifiableAzureAccessToken_Detection covers the
// classifier added by the followup fix. Pure-function unit test for the
// Microsoft proprietary marker we rely on (nonce in JWT header).
func TestIssue134_Followup_IsUnverifiableAzureAccessToken_Detection(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const kid = "azure-detection-kid"
	standardToken, err := createTestJWT(rsaKey, "RS256", kid, map[string]any{
		"iss": "https://login.microsoftonline.com/tenant-id/v2.0",
		"aud": "test-client-id",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"sub": "user-azure-id",
	})
	require.NoError(t, err)

	graphToken := signGraphStyleAccessToken(t, rsaKey, kid, "wire-only-nonce", map[string]any{
		"iss": "https://login.microsoftonline.com/tenant-id/v2.0",
		"aud": "00000003-0000-0000-c000-000000000000",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"sub": "user-azure-id",
		"scp": "User.Read",
	})

	oidc, _ := newAzureFollowupOIDC(t, &JWKSet{})

	cases := []struct {
		name           string
		token          string
		wantUnverified bool
	}{
		{name: "standard JWT without nonce header", token: standardToken, wantUnverified: false},
		{name: "Microsoft proprietary token (nonce in header)", token: graphToken, wantUnverified: true},
		{name: "garbage token treated as unverifiable", token: "not-a-jwt-at-all", wantUnverified: true},
		{name: "empty token treated as unverifiable", token: "", wantUnverified: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := oidc.isUnverifiableAzureAccessToken(tc.token)
			assert.Equal(t, tc.wantUnverified, got)
		})
	}
}

// TestIssue134_Followup_StandardAzureAccessTokenStillVerifies guards against
// regression in the happy path: an access token issued for our own clientID
// (custom Azure-registered API) — no proprietary nonce header, signed normally
// — must still flow through the standard verification path and authenticate.
func TestIssue134_Followup_StandardAzureAccessTokenStillVerifies(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const kid = "azure-standard-kid"
	jwk := JWK{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
		N: base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}
	jwks := &JWKSet{Keys: []JWK{jwk}}

	now := time.Now()
	exp := now.Add(time.Hour).Unix()

	// Custom-resource access token: aud points to the app, no nonce header.
	accessToken, err := createTestJWT(rsaKey, "RS256", kid, map[string]any{
		"iss": "https://login.microsoftonline.com/tenant-id/v2.0",
		"aud": "test-client-id",
		"exp": exp,
		"iat": now.Add(-2 * time.Minute).Unix(),
		"nbf": now.Add(-2 * time.Minute).Unix(),
		"sub": "user-azure-id",
		"scp": "api.read",
		"jti": "standard-access-jti",
	})
	require.NoError(t, err)

	idToken, err := createTestJWT(rsaKey, "RS256", kid, map[string]any{
		"iss":   "https://login.microsoftonline.com/tenant-id/v2.0",
		"aud":   "test-client-id",
		"exp":   exp,
		"iat":   now.Add(-2 * time.Minute).Unix(),
		"nbf":   now.Add(-2 * time.Minute).Unix(),
		"sub":   "user-azure-id",
		"email": "user@example.com",
		"nonce": "id-token-oidc-nonce",
		"jti":   "standard-id-jti",
	})
	require.NoError(t, err)

	oidc, errBuf := newAzureFollowupOIDC(t, jwks)
	session := authedSessionWithTokens(t, accessToken, idToken)

	authenticated, needsRefresh, expired := oidc.validateAzureTokens(session)

	assert.True(t, authenticated, "standard Azure access token must verify and authenticate")
	assert.False(t, needsRefresh)
	assert.False(t, expired)
	assert.NotContains(t, errBuf.String(), "crypto/rsa: verification error",
		"standard Azure token must not produce signature errors")
}

// TestIssue134_Followup_GraphAccessTokenWithoutIDToken covers the edge where
// the session has only a Graph access token (no ID token). The classifier must
// preserve the existing "treat as opaque" semantics for backward compatibility:
// authenticated=true even when there is no ID token to verify.
func TestIssue134_Followup_GraphAccessTokenWithoutIDToken(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const kid = "azure-no-idt-kid"
	jwk := JWK{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
		N: base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}
	jwks := &JWKSet{Keys: []JWK{jwk}}

	graphAccessToken := signGraphStyleAccessToken(t, rsaKey, kid, "wire-only-nonce-no-idt", map[string]any{
		"iss": "https://login.microsoftonline.com/tenant-id/v2.0",
		"aud": "00000003-0000-0000-c000-000000000000",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"sub": "user-azure-id",
		"scp": "User.Read",
	})

	oidc, errBuf := newAzureFollowupOIDC(t, jwks)
	session := authedSessionWithTokens(t, graphAccessToken, "")

	authenticated, needsRefresh, expired := oidc.validateAzureTokens(session)

	assert.True(t, authenticated, "Graph token without ID token must remain authenticated (matches existing opaque-token semantics)")
	assert.False(t, needsRefresh)
	assert.False(t, expired)
	assert.NotContains(t, errBuf.String(), "crypto/rsa: verification error")
}

// TestIssue134_Followup_ConfusedDeputyAttackDoesNotBypassVerification proves
// the classifier is not a security regression. An attacker who forges a JWT
// with a `nonce` JWT header (Microsoft's proprietary marker) but a payload
// claiming `aud=our-clientID` should NOT gain authenticated status simply by
// triggering the "treat as opaque" branch.
//
// This is the confused-deputy guardrail Microsoft warns about
// (https://cwe.mitre.org/data/definitions/441.html): we treat the access token
// as opaque, which means we DO NOT authorize from it — authorization comes
// only from a separately verifiable ID token.  An attacker without a valid ID
// token must not be authenticated.
func TestIssue134_Followup_ConfusedDeputyAttackDoesNotBypassVerification(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const kid = "azure-attack-kid"
	jwk := JWK{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
		N: base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}
	jwks := &JWKSet{Keys: []JWK{jwk}}

	// Forged: attacker uses their OWN key, sets aud = our clientID, plants a
	// `nonce` header to trip the opaque-detection path.
	forgedAccessToken := signGraphStyleAccessToken(t, attackerKey, kid, "attacker-nonce", map[string]any{
		"iss": "https://login.microsoftonline.com/tenant-id/v2.0",
		"aud": "test-client-id",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"sub": "attacker",
		"scp": "admin",
	})

	// Forged ID token signed with the attacker's key — must fail verification
	// against the tenant JWKS.
	forgedIDToken, err := createTestJWT(attackerKey, "RS256", kid, map[string]any{
		"iss":   "https://login.microsoftonline.com/tenant-id/v2.0",
		"aud":   "test-client-id",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Add(-2 * time.Minute).Unix(),
		"nbf":   time.Now().Add(-2 * time.Minute).Unix(),
		"sub":   "attacker",
		"email": "attacker@evil.example",
		"nonce": "id-token-oidc-nonce",
		"jti":   "attacker-id-jti",
	})
	require.NoError(t, err)

	oidc, _ := newAzureFollowupOIDC(t, jwks)
	session := authedSessionWithTokens(t, forgedAccessToken, forgedIDToken)

	authenticated, _, _ := oidc.validateAzureTokens(session)
	assert.False(t, authenticated,
		"attacker's forged tokens must not authenticate even when the access token has a nonce header — ID token verification rejects the wrong-key signature")
}
