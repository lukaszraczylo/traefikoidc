package traefikoidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssue134_AzureRSAJWKSDistributedCacheNoFloatError reproduces and
// verifies the fix for issue #134.
//
// Symptom (before fix): with a Redis backend wired into UniversalCache,
// caching the parsed *parsedJWKS triggered:
//
//	json: cannot unmarshal number 2251513...
//	  into Go value of type float64
//
// Root cause: under yaegi, json.Marshal of a struct exposes unexported
// fields with an X-prefixed name. parsedJWKS{ keys map[string]crypto.PublicKey }
// thus serialized the inner *rsa.PublicKey, whose modulus *big.Int marshals
// as a JSON number hundreds of digits long. On read, json.Unmarshal into
// interface{} parses numbers as float64, which cannot represent that range.
// The user saw the error log on every request even though auth still worked
// (fallback path rebuilt the keys in memory).
//
// Fix: route both *JWKSet and *parsedJWKS through SetLocal/GetLocal — the
// distributed backend never sees them.
func TestIssue134_AzureRSAJWKSDistributedCacheNoFloatError(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	redisCfg := backends.DefaultRedisConfig(mr.Addr())
	redisCfg.RedisPrefix = "issue134:"
	backend, err := backends.NewRedisBackend(redisCfg)
	require.NoError(t, err)
	defer backend.Close()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "azure-test-kid"
	jwk := JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big2bytes(rsaKey.E)),
	}

	var fetchCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetchCount, 1)
		_ = json.NewEncoder(w).Encode(JWKSet{Keys: []JWK{jwk}})
	}))
	defer server.Close()

	errBuf := &bytes.Buffer{}
	infoBuf := &bytes.Buffer{}
	logger := &Logger{
		logError: log.New(errBuf, "", 0),
		logInfo:  log.New(infoBuf, "", 0),
		logDebug: log.New(io.Discard, "", 0),
	}

	cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:    CacheTypeJWK,
		MaxSize: 100,
		Logger:  logger,
	}, backend)
	defer cache.Close()

	jwkCache := &JWKCache{cache: cache}
	ctx := context.Background()

	pub1, err := jwkCache.GetPublicKey(ctx, server.URL, kid, http.DefaultClient)
	require.NoError(t, err, "first GetPublicKey should succeed")
	require.NotNil(t, pub1)
	gotRSA, ok := pub1.(*rsa.PublicKey)
	require.True(t, ok, "returned key should be *rsa.PublicKey, got %T", pub1)
	assert.Equal(t, 0, rsaKey.N.Cmp(gotRSA.N), "modulus must survive intact")
	assert.Equal(t, rsaKey.E, gotRSA.E, "exponent must survive intact")

	pub2, err := jwkCache.GetPublicKey(ctx, server.URL, kid, http.DefaultClient)
	require.NoError(t, err, "second GetPublicKey should succeed")
	require.True(t, samePublicKey(pub1, pub2), "second call must return the same parsed key (cache hit)")

	assert.Equal(t, int32(1), atomic.LoadInt32(&fetchCount),
		"upstream JWKS endpoint must be hit exactly once; second call must be served from local cache")

	errOutput := errBuf.String()
	assert.NotContains(t, errOutput, "Failed to deserialize",
		"deserialize error must not appear with the fix in place; got: %s", errOutput)
	assert.NotContains(t, errOutput, "into Go value of type float64",
		"float64 unmarshal error must not appear; got: %s", errOutput)

	parsedKey := server.URL + parsedKeysSuffix
	jwksKey := server.URL
	for _, k := range []string{cache.prefixKey(parsedKey), cache.prefixKey(jwksKey)} {
		fullKey := redisCfg.RedisPrefix + k
		assert.False(t, mr.Exists(fullKey),
			"key %q must not exist in Redis (local-only caching); got %v", fullKey, mr.Keys())
	}
}

// TestIssue134_StalePoisonedRedisDataIgnored verifies that pre-existing bad
// data left in Redis under a JWK :parsed key from a prior buggy version is
// ignored: the local-only fix never reads that key, so no log spam, and the
// fallback path returns a real *rsa.PublicKey.
func TestIssue134_StalePoisonedRedisDataIgnored(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	redisCfg := backends.DefaultRedisConfig(mr.Addr())
	redisCfg.RedisPrefix = "issue134stale:"
	backend, err := backends.NewRedisBackend(redisCfg)
	require.NoError(t, err)
	defer backend.Close()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "azure-test-kid"
	jwk := JWK{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
		N: base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big2bytes(rsaKey.E)),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(JWKSet{Keys: []JWK{jwk}})
	}))
	defer server.Close()

	// Pre-poison Redis with the kind of payload the old buggy path would have
	// produced (huge unquoted JSON number for the modulus). With the fix the
	// JWKCache must not even read this key.
	poisoned := []byte("\x01" + strings.Replace(
		`{"Xkeys":{"azure-test-kid":{"N":NUMBER,"E":65537}}}`,
		"NUMBER", rsaKey.N.String(), 1,
	))
	parsedRedisKey := redisCfg.RedisPrefix + "jwk:" + server.URL + parsedKeysSuffix
	require.NoError(t, mr.Set(parsedRedisKey, string(poisoned)))

	errBuf := &bytes.Buffer{}
	logger := &Logger{
		logError: log.New(errBuf, "", 0),
		logInfo:  log.New(io.Discard, "", 0),
		logDebug: log.New(io.Discard, "", 0),
	}

	cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:    CacheTypeJWK,
		MaxSize: 100,
		Logger:  logger,
	}, backend)
	defer cache.Close()

	jwkCache := &JWKCache{cache: cache}
	pub, err := jwkCache.GetPublicKey(context.Background(), server.URL, kid, http.DefaultClient)
	require.NoError(t, err)
	require.NotNil(t, pub)
	gotRSA, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, 0, rsaKey.N.Cmp(gotRSA.N))

	assert.NotContains(t, errBuf.String(), "Failed to deserialize",
		"poisoned Redis entry must not be touched; got error log: %s", errBuf.String())
}

// TestIssue134_SetLocalGetLocalSkipBackend verifies the new SetLocal/GetLocal
// pair never reads or writes the configured backend.
func TestIssue134_SetLocalGetLocalSkipBackend(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	redisCfg := backends.DefaultRedisConfig(mr.Addr())
	redisCfg.RedisPrefix = "local:"
	backend, err := backends.NewRedisBackend(redisCfg)
	require.NoError(t, err)
	defer backend.Close()

	cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:    CacheTypeGeneral,
		MaxSize: 10,
		Logger:  GetSingletonNoOpLogger(),
	}, backend)
	defer cache.Close()

	type unsafeShape struct {
		hidden map[string]interface{}
	}
	val := &unsafeShape{hidden: map[string]interface{}{"k": 1}}

	require.NoError(t, cache.SetLocal("local-key", val, 1*time.Hour))

	got, found := cache.GetLocal("local-key")
	require.True(t, found)
	assert.Same(t, val, got, "GetLocal must return the exact pointer stored, no JSON round-trip")

	for _, k := range mr.Keys() {
		assert.NotContains(t, k, "local-key",
			"SetLocal must not write to Redis; found key %q (all keys: %v)", k, mr.Keys())
	}

	cache.mu.Lock()
	delete(cache.items, "local-key")
	cache.lruList.Init()
	cache.currentSize = 0
	cache.currentMemory = 0
	cache.mu.Unlock()

	_, found = cache.GetLocal("local-key")
	assert.False(t, found, "GetLocal must not fall back to backend after local cache cleared")
}

// big2bytes returns the big-endian byte slice for a positive int.
func big2bytes(e int) []byte {
	if e <= 0 {
		return []byte{}
	}
	var buf []byte
	for e > 0 {
		buf = append([]byte{byte(e & 0xff)}, buf...)
		e >>= 8
	}
	return buf
}

// samePublicKey reports whether two crypto.PublicKey instances represent the
// same RSA key, used to confirm cache hits return identical reconstructed
// keys.
func samePublicKey(a, b interface{}) bool {
	ar, ok1 := a.(*rsa.PublicKey)
	br, ok2 := b.(*rsa.PublicKey)
	if !ok1 || !ok2 {
		return false
	}
	return ar.N.Cmp(br.N) == 0 && ar.E == br.E
}
