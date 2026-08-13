package traefikoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

// TestJWKSRotationPickedUpOnKidMiss reproduces the key-rotation availability
// bug: after the IdP rotates signing keys and issues a NEW kid, GetPublicKey
// must pick the new key up promptly (bounded live refresh) instead of
// returning "no matching public key found for kid" for up to the 1h cache
// TTL because the stale cached keyset is reused.
func TestJWKSRotationPickedUpOnKidMiss(t *testing.T) {
	require := require.New(t)

	// Two RSA key pairs: keyA is the "pre-rotation" key, keyB the rotated one.
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(err)
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(err)

	// The server serves kidA until the atomic flag is set, then kidB.
	var rotated int32
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if atomic.LoadInt32(&rotated) == 1 {
			writeJWKS(t, w, "kidB", &keyB.PublicKey)
			return
		}
		writeJWKS(t, w, "kidA", &keyA.PublicKey)
	}))
	defer srv.Close()

	cache := NewJWKCache()

	// Seed the raw cache with the pre-rotation keyset (as happens on a cold
	// start), WITHOUT taking the kid-miss force path.
	_, err = cache.GetJWKS(context.Background(), srv.URL, http.DefaultClient)
	require.NoError(err)

	// Pre-rotation token for kidA resolves fine.
	_, err = cache.GetPublicKey(context.Background(), srv.URL, "kidA", http.DefaultClient)
	require.NoError(err, "pre-rotation kid should resolve")

	// Simulate a long-lived process: the key rotation happens well after the
	// process start (and thus well after any earlier live fetch), so the
	// force-refresh cooldown has long expired.
	cache.forceMu.Lock()
	cache.lastForceRefresh[srv.URL] = time.Time{}
	cache.forceMu.Unlock()

	// Provider rotates keys; now issues a token with the NEW kid.
	atomic.StoreInt32(&rotated, 1)

	// The new kid must be resolved now (bounded live refresh on kid-miss),
	// not after the 1-hour cache TTL.
	pub, err := cache.GetPublicKey(context.Background(), srv.URL, "kidB", http.DefaultClient)
	require.NoError(err, "post-rotation new kid must be picked up promptly")
	require.NotNil(pub)
	require.Equal(&keyB.PublicKey, pub, "resolved key must be the rotated key")
}

// TestJWKSRotationBoundRefetch verifies the cooldown bounds repeated live
// fetches when an attacker presents bogus unknown kids, while a real rotation
// still succeeds on the first new-kid request.
func TestJWKSRotationBoundRefetch(t *testing.T) {
	require := require.New(t)

	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(err)

	var fetches int32
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		atomic.AddInt32(&fetches, 1)
		writeJWKS(t, w, "kidA", &keyA.PublicKey)
	}))
	defer srv.Close()

	cache := NewJWKCache()

	// First kid-miss forces exactly one live fetch and returns "no key".
	_, err = cache.GetPublicKey(context.Background(), srv.URL, "bogus1", http.DefaultClient)
	require.Error(err)

	// Within the cooldown window, further bogus kids must NOT each trigger a
	// live fetch (amplification bound) — they reuse the freshly cached set.
	_, err = cache.GetPublicKey(context.Background(), srv.URL, "bogus2", http.DefaultClient)
	require.Error(err)

	time.Sleep(100 * time.Millisecond)
	require.Equal(int32(1), atomic.LoadInt32(&fetches), "only one live fetch within the cooldown window")
}

func writeJWKS(t *testing.T, w http.ResponseWriter, kid string, pub *rsa.PublicKey) {
	t.Helper()
	jwk := JWK{
		Kty: "RSA",
		Kid: kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
	_ = json.NewEncoder(w).Encode(JWKSet{Keys: []JWK{jwk}})
}
