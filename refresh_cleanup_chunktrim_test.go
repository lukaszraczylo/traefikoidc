package traefikoidc

import (
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// Cleanup must not evict a tracker whose cooldown is still running.
func TestRefreshCleanupKeepsTrackerInCooldown(t *testing.T) {
	cfg := DefaultRefreshCoordinatorConfig()
	cfg.MaxRefreshAttempts = 2
	cfg.RefreshAttemptWindow = 20 * time.Millisecond
	cfg.RefreshCooldownPeriod = time.Hour
	rc := NewRefreshCoordinator(cfg, GetSingletonNoOpLogger())
	defer rc.Shutdown()

	rc.recordRefreshAttempt("s")
	rc.recordRefreshAttempt("s")
	if !rc.isInCooldown("s") {
		t.Fatal("precondition: session must enter cooldown")
	}
	time.Sleep(80 * time.Millisecond)
	rc.cleanupStaleEntries()
	if !rc.isInCooldown("s") {
		t.Fatal("cleanup evicted a tracker still in cooldown")
	}
}

// Stale chunks above token_total must be dropped by key, even when the key
// set is sparse.
func TestChunkTrimDropsStaleSparseKeys(t *testing.T) {
	cm := NewChunkManager(newNoOpLogger())
	mk := func(s string, total interface{}) *sessions.Session {
		v := map[interface{}]interface{}{"token_chunk": s}
		if total != nil {
			v["token_total"] = total
		}
		return &sessions.Session{Values: v}
	}
	chunks := map[int]*sessions.Session{
		0: mk("Zq8xK2mP", 3), 1: mk("r7TnB4wY", nil), 2: mk("c9LdG5sH", nil), 7: mk("stale", nil),
	}
	res := cm.processChunkedToken(chunks, RefreshTokenConfig)
	if res.Error != nil || res.Token != "Zq8xK2mPr7TnB4wYc9LdG5sH" {
		t.Fatalf("token=%q err=%v, want Zq8xK2mPr7TnB4wYc9LdG5sH", res.Token, res.Error)
	}
}
