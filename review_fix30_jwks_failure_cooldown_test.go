package traefikoidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestJWKSFailureCooldown_BoundsRepeatFetches pins FIX-30: while the JWKS
// endpoint is failing, two unknown-kid public-key lookups within the short
// failure cooldown window must trigger exactly one upstream fetch. At head,
// doLiveRefresh records the force-refresh cooldown only after a SUCCESSFUL
// fetch (jwk.go R100 comment), so a failing IdP is hit again on every
// unknown-kid request with no throttling at all.
func TestJWKSFailureCooldown_BoundsRepeatFetches(t *testing.T) {
	var fetchCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&fetchCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cache := NewJWKCache()
	ctx := context.Background()
	client := server.Client()

	_, err1 := cache.GetPublicKey(ctx, server.URL, "unknown-kid-1", client)
	assert.Error(t, err1, "first lookup against a failing JWKS endpoint must return an error")

	_, err2 := cache.GetPublicKey(ctx, server.URL, "unknown-kid-2", client)
	assert.Error(t, err2, "second lookup against a failing JWKS endpoint must return an error")

	assert.Equal(t, int64(1), atomic.LoadInt64(&fetchCount),
		"two unknown-kid lookups within the failure cooldown window must produce exactly one upstream JWKS fetch")
}
