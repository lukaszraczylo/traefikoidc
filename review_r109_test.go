package traefikoidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// signRSAJWTForTest builds an RS256-signed JWT with the given kid and claims,
// suitable for exercising real signature verification (unlike makeJWTForTest
// which uses alg=none).
func signRSAJWTForTest(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	payload, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hasher := sha256.New()
	hasher.Write([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hasher.Sum(nil))
	require.NoError(t, err)
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestVerifyToken_RefreshOnSignatureFailureAfterRotation regresses the key-rotation
// availability gap: when an IdP rotates its signing key while REUSING the same
// kid, VerifyJWTSignatureAndClaims first resolves the (now-stale) cached key and
// signature verification fails. It must refresh the JWKS once and retry before
// returning an error — otherwise tokens are rejected as invalid (401) for up to
// the 1h JWKS cache TTL after an in-place rotation.
func TestVerifyToken_RefreshOnSignatureFailureAfterRotation(t *testing.T) {
	require := require.New(t)

	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(err)
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(err)

	const kid = "rotated-shared-kid"

	// Server serves keyA until rotation, then keyB (same kid).
	var rotated int32
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if atomic.LoadInt32(&rotated) == 1 {
			writeJWKS(t, w, kid, &keyB.PublicKey)
			return
		}
		writeJWKS(t, w, kid, &keyA.PublicKey)
	}))
	defer srv.Close()

	cache := NewJWKCache()

	// Seed the cache with the pre-rotation key so GetPublicKey's fast path
	// serves the now-stale keyA (mirrors a long-running process that fetched
	// the JWKS before rotation, well within the 1h TTL).
	_, err = cache.GetPublicKey(context.Background(), srv.URL, kid, http.DefaultClient)
	require.NoError(err)

	now := time.Now()
	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"sub": "user-1",
		"aud": "audience1",
		"exp": now.Add(2 * time.Hour).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
	}

	// Provider rotates keys in place, reusing the same kid; issues a token
	// signed with the new key.
	atomic.StoreInt32(&rotated, 1)
	token := signRSAJWTForTest(t, keyB, kid, claims)

	parsed, err := parseJWT(token)
	require.NoError(err)

	oidc := &TraefikOidc{
		jwkCache:               cache,
		jwksURL:                srv.URL,
		issuerURL:              "https://issuer.example.com",
		audience:               "audience1",
		clientID:               "client123",
		httpClient:             http.DefaultClient,
		suppressDiagnosticLogs: true,
	}

	// OLD: signature fails against the stale cached keyA -> error (401 until
	// the JWKS cache expires). NEW: refresh-once fetches keyB and succeeds.
	require.NoError(oidc.VerifyJWTSignatureAndClaims(parsed, token),
		"token signed with the rotated key (same kid) must verify after a JWKS refresh")
}
