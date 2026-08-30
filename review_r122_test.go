package traefikoidc

import (
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestRefreshCoordinator_IsUnderMemoryPressureUsesOwnThreshold guards the R122
// fix to refresh_coordinator.go: isUnderMemoryPressure consulted the GLOBAL
// memory monitor's alert level (driven by the shared 256MB "High" heap
// threshold, and only populated once real sampling runs) instead of the
// coordinator's OWN MemoryPressureThresholdMB. That meant (a) the operator's
// configured threshold was ignored entirely, and (b) in a shared process
// where real heap crosses 256MB every request was silently denied. The gate
// must compare current heap against the coordinator's own threshold.
func TestRefreshCoordinator_IsUnderMemoryPressureUsesOwnThreshold(t *testing.T) {
	// Pin the global monitor's stats to a deterministic 3MB heap for the
	// duration of this test (restored below). The original test assumed
	// "any real heap exceeds 1MB", which broke under -shuffle when the
	// real heap was below the threshold (GetCurrentStats returns the
	// global monitor's cached, possibly-stale snapshot) — an intermittent
	// CI failure with no production cause (R196).
	mm := GetGlobalMemoryMonitor()
	mm.mu.Lock()
	old := mm.lastStats
	mm.lastStats = &MemoryStats{HeapAllocBytes: 3 * (1 << 20)} // 3MB
	mm.mu.Unlock()
	t.Cleanup(func() {
		mm.mu.Lock()
		mm.lastStats = old
		mm.mu.Unlock()
	})

	// Threshold 1MB: pinned heap (3MB) exceeds it -> under pressure.
	cfg := DefaultRefreshCoordinatorConfig()
	cfg.MemoryPressureThresholdMB = 1
	rc := NewRefreshCoordinator(cfg, GetSingletonNoOpLogger())
	if !rc.isUnderMemoryPressure() {
		t.Fatal("coordinator with a 1MB threshold must report under memory pressure for a 3MB heap")
	}

	// Threshold 1TB: never under pressure.
	cfg2 := DefaultRefreshCoordinatorConfig()
	cfg2.MemoryPressureThresholdMB = 1 << 20 // 1,048,576 MB
	rc2 := NewRefreshCoordinator(cfg2, GetSingletonNoOpLogger())
	if rc2.isUnderMemoryPressure() {
		t.Fatal("coordinator with a ~1TB threshold must not report under memory pressure")
	}
}

// TestRegisterBackgroundTask_ReplacesNeverStartedTask guards the R122 fix to
// singleton_resources.go: RegisterBackgroundTask kept an existing task when
// stopped==0, but a task whose startOnce was consumed without ever starting
// (Start rejected by the circuit breaker: started==0, stopped==0) has
// stopped==0 too, so it was kept and StartBackgroundTask became a permanent
// no-op (Start is sync.Once-guarded), leaving the singleton task dead until
// restart. The keep-condition must require started==1.
func TestRegisterBackgroundTask_ReplacesNeverStartedTask(t *testing.T) {
	rm := &ResourceManager{
		tasks:  map[string]*BackgroundTask{},
		logger: GetSingletonNoOpLogger(),
	}
	const name = "replace-never-started"

	// A task in the never-started state (started==0, stopped==0): its
	// Start was consumed via a circuit-breaker rejection. Re-registering
	// must REPLACE it so a later Start can actually run it.
	dead := NewBackgroundTask(name, time.Hour, func() {}, rm.logger, &rm.wg)
	atomic.StoreInt32(&dead.started, 0)
	atomic.StoreInt32(&dead.stopped, 0)
	rm.tasks[name] = dead

	if err := rm.RegisterBackgroundTask(name, time.Hour, func() {}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if rm.tasks[name] == dead {
		t.Fatal("a never-started task (started==0, stopped==0) must be REPLACED, otherwise Start is a permanent no-op")
	}

	// An actively running task (started==1, stopped==0) must be kept.
	running := NewBackgroundTask("running", time.Hour, func() {}, rm.logger, &rm.wg)
	atomic.StoreInt32(&running.started, 1)
	atomic.StoreInt32(&running.stopped, 0)
	rm.tasks["running"] = running

	if err := rm.RegisterBackgroundTask("running", time.Hour, func() {}); err != nil {
		t.Fatalf("register running: %v", err)
	}
	if rm.tasks["running"] != running {
		t.Fatal("an actively running task must be kept (idempotent re-registration)")
	}
}

// TestSetAccessToken_PreservesOldTokenOnChunkAbort guards the R122 fix to
// session.go: the chunked-write branch of SetAccessToken cleared the
// existing token (accessSession.Values["token"] and accessTokenChunks)
// BEFORE validating the new token's chunks. On any abort (here: >50
// chunks, since maxCookieSize=1400 and the token crosses 50*1400=
// 70KB with compression still < 100KB) the previous valid access token
// was left nowhere, GetAccessToken returned "", and the user was forced
// to re-authenticate. The clear now happens only after validation.
func TestSetAccessToken_PreservesOldTokenOnChunkAbort(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, NewLogger("error"))
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	sess, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	t.Cleanup(sess.returnToPoolSafely)

	const small = "smallaccesstokenvaluevaluevalue"
	sess.SetAccessToken(small)
	if got := sess.GetAccessToken(); got != small {
		t.Fatalf("precondition: small token must be retrievable, got %q", got)
	}

	// Incompressible payload large enough that compressed size lands
	// between 50*maxCookieSize (70KB) and the 100KB cap, so the chunked
	// branch splits into >50 chunks and aborts after too-many-chunks.
	blob := make([]byte, 60*1024)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	bigToken := base64.StdEncoding.EncodeToString(blob)

	sess.SetAccessToken(bigToken)

	if got := sess.GetAccessToken(); got != small {
		t.Fatalf("old access token must be preserved when storing a new oversized token fails, got %q", got)
	}
}
