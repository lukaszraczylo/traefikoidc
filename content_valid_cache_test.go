package traefikoidc

import (
	"strings"
	"testing"
	"time"
)

func TestContentValidCache(t *testing.T) {
	cm := NewChunkManager(NewLogger(""))
	t.Cleanup(cm.Shutdown)
	now := time.Now()
	valid := tokenWithGroups(t, map[string]interface{}{"sub": "a", "exp": float64(now.Add(time.Hour).Unix()), "iat": float64(now.Unix())})
	futureIat := tokenWithGroups(t, map[string]interface{}{"sub": "b", "exp": float64(now.Add(2 * time.Hour).Unix()), "iat": float64(now.Add(time.Hour).Unix())})
	badContent := jwtLike("eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJ4In0", "c2ln\x01bmF0dXJlLXZhbHVl")

	t.Run("valid token passes twice and is cached", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			if res := cm.validateToken(valid, AccessTokenConfig); res.Error != nil {
				t.Fatalf("pass %d: %v", i, res.Error)
			}
		}
		if _, ok := cm.cachedTokenTimes(contentValidKey(valid, AccessTokenConfig)); !ok {
			t.Fatal("valid token was not cached")
		}
	})
	t.Run("cache is per token type", func(t *testing.T) {
		if _, ok := cm.cachedTokenTimes(contentValidKey(valid, IDTokenConfig)); ok {
			t.Fatal("access-token entry leaked into the ID-token key")
		}
	})
	t.Run("time checks still run on a cache hit", func(t *testing.T) {
		cm.markContentValid(contentValidKey(futureIat, AccessTokenConfig), cm.tokenTimesOf(futureIat))
		res := cm.validateToken(futureIat, AccessTokenConfig)
		if res.Error == nil || !strings.Contains(res.Error.Error(), "issued in future") {
			t.Fatalf("error = %v, want issued-in-future through the content cache", res.Error)
		}
	})
	t.Run("cache hit uses the stored claims", func(t *testing.T) {
		other := tokenWithGroups(t, map[string]interface{}{"sub": "c", "exp": float64(now.Add(time.Hour).Unix()), "iat": float64(now.Unix())})
		future := now.Add(time.Hour)
		cm.markContentValid(contentValidKey(other, AccessTokenConfig), tokenTimes{jwt: true, iat: &future})
		res := cm.validateToken(other, AccessTokenConfig)
		if res.Error == nil || !strings.Contains(res.Error.Error(), "issued in future") {
			t.Fatalf("error = %v, want the cached iat to drive the freshness check", res.Error)
		}
	})
	t.Run("invalid content never cached", func(t *testing.T) {
		if res := cm.validateToken(badContent, AccessTokenConfig); res.Error == nil {
			t.Fatal("control character accepted")
		}
		if _, ok := cm.cachedTokenTimes(contentValidKey(badContent, AccessTokenConfig)); ok {
			t.Fatal("invalid token was cached")
		}
	})
	t.Run("cache stays bounded", func(t *testing.T) {
		for i := 0; i < contentValidCacheMax+10; i++ {
			cm.markContentValid(contentValidKey(strings.Repeat("x", i%7)+string(rune('a'+i%26))+strings.Repeat("y", i/26), AccessTokenConfig), tokenTimes{})
		}
		cm.contentMu.Lock()
		n := len(cm.contentValid)
		cm.contentMu.Unlock()
		if n > contentValidCacheMax {
			t.Fatalf("cache size %d exceeds %d", n, contentValidCacheMax)
		}
	})
}
