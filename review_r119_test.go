package traefikoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// TestRefreshToken_PersistsRotatedRefreshTokenOnClaimsExtractFailure guards the
// R119 fix: the ONE rotation-persistence branch R116 missed. Rotation IdPs
// consume the presented refresh token on EVERY successful token exchange,
// regardless of whether the follow-up claims extraction of the newly issued
// ID token succeeds. refreshToken returns false here (claims can't be
// extracted), so without persisting the just-rotated token the next refresh
// presents a consumed token, hits invalid_grant, and forces a re-login.
func TestRefreshToken_PersistsRotatedRefreshTokenOnClaimsExtractFailure(t *testing.T) {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		NewLogger("error"),
	)
	require.NoError(t, err)
	defer sessionManager.Shutdown()

	tOidc := &TraefikOidc{
		logger:              NewLogger("error"),
		userIdentifierClaim: "email",
		sessionManager:      sessionManager,
		tokenExchanger: &EnhancedMockTokenExchanger{
			RefreshResponse: &TokenResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "rotated-refresh-token",
				IDToken:      "new-id-token-jwt",
				ExpiresIn:    3600,
			},
		},
		// ID-token verification passes; it is the CLAIMS EXTRACTION that fails.
		tokenVerifier: &EnhancedMockTokenVerifier{},
		extractClaimsFunc: func(token string) (map[string]any, error) {
			return nil, errors.New("claims decode failed")
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rw := httptest.NewRecorder()

	session, err := sessionManager.GetSession(req)
	require.NoError(t, err)
	defer session.returnToPoolSafely()

	session.SetRefreshToken("initial-refresh-token")

	refreshed := tOidc.refreshToken(rw, req, session)
	require.False(t, refreshed, "refreshToken must report failure when claims cannot be extracted")

	got := session.GetRefreshToken()
	require.Equal(t, "rotated-refresh-token", got,
		"rotated refresh token must be salvaged even when claims extraction fails")
}

// TestReplay_Set_NoRaceWithCleanup guards the R119 fix: the shardedReplayCache
// singleton read in verifyTokenWithOpts was previously unsynchronized
// (token_manager.go), while cleanupReplayCache nils it under the write lock
// (jwt.go). The sibling replay path in jwt.go already holds replayCacheMu.RLock
// around the read; this closes the one remaining unguarded reader. Run under
// -race: OLD reports a data race (or nil-deref), NEW is clean.
func TestReplay_Set_NoRaceWithCleanup(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "replay-kid"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJWKS(t, w, kid, &key.PublicKey)
	}))
	defer srv.Close()

	cache := NewJWKCache()
	_, err = cache.GetPublicKey(context.Background(), srv.URL, kid, http.DefaultClient)
	require.NoError(t, err)

	now := time.Now()
	oidc := &TraefikOidc{
		jwkCache:               cache,
		jwksURL:                srv.URL,
		issuerURL:              "https://issuer.example.com",
		audience:               "aud",
		clientID:               "client123",
		httpClient:             http.DefaultClient,
		suppressDiagnosticLogs: true,
		tokenCache:             NewTokenCache(),
		tokenBlacklist:         NewCache(),
		limiter:                rate.NewLimiter(rate.Every(time.Second), 1000),
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; ; j++ {
				select {
				case <-stop:
					return
				default:
				}
				claims := map[string]any{
					"iss": "https://issuer.example.com",
					"sub": fmt.Sprintf("user-%d", n),
					"aud": "aud",
					"exp": now.Add(time.Hour).Unix(),
					"iat": now.Add(-time.Minute).Unix(),
					"jti": fmt.Sprintf("jti-%d-%d", n, j),
				}
				// Signature is genuinely verified via the real JWKS, so the
				// replay-marking block (which reads shardedReplayCache) runs.
				_ = oidc.verifyTokenWithOpts(signRSAJWTForTest(t, key, kid, claims), verifyOpts{})
			}
		}(i)
	}

	// Cleanup nils shardedReplayCache under the write lock while the verifiers
	// read it concurrently.
	for i := 0; i < 300; i++ {
		cleanupReplayCache()
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
}
