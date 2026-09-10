package traefikoidc

import (
	"context"
	"testing"
	"time"
)

// FIX-18: main.go wires up TWO GracefulDegradation instances per plugin
// instance — one directly via NewErrorRecoveryManager (t.errorRecoveryManager)
// and one nested inside NewTokenResilienceManager's own ErrorRecoveryManager
// (t.tokenResilienceManager). Production Close() only ever closed the first
// one (t.errorRecoveryManager.gracefulDegradation.Close()), so the second gd
// leaked forever in the package-level gdInstances registry and the shared
// "graceful-degradation-health-check" task's last-instance stop gate
// (len(gdInstances.set)==0) never fired.
//
// gdInstancesLen (below) reads the size of the package-level gdInstances set.
// The test asserts on the DELTA around creating and closing both managers, so
// it stays correct regardless of what other tests in this package leave
// registered.
func TestFix18_ClosingBothManagersEmptiesGDInstances(t *testing.T) {
	logger := GetSingletonNoOpLogger()

	before := gdInstancesLen()

	erm := NewErrorRecoveryManager(logger)
	trm := NewTokenResilienceManager(DefaultTokenResilienceConfig(), logger)

	afterNew := gdInstancesLen()
	if afterNew != before+2 {
		t.Fatalf("precondition: wiring one plugin instance must create exactly 2 GracefulDegradation instances (one direct, one nested in TokenResilienceManager); got delta %d", afterNew-before)
	}

	// Let each instance's async health-check goroutine (started by
	// NewGracefulDegradation) settle — either it assigns the shared task, or
	// it observes an already-closed instance and bails — before closing.
	// This makes the Close() calls below exercise the real "task already
	// assigned, stop it by name" path deterministically on every run instead
	// of sometimes racing the goroutine (FIX-18 review, item 4).
	waitForHealthRoutineSettled(t, erm.gracefulDegradation)
	waitForHealthRoutineSettled(t, trm.errorRecoveryManager.gracefulDegradation)

	// Close every gd this wiring created. Before FIX-18, only erm's gd had a
	// Close path reachable from TraefikOidc.Close (via
	// t.errorRecoveryManager.gracefulDegradation.Close()); trm's own gd had
	// no Close method to call at all.
	erm.Close()
	trm.Close()

	afterClose := gdInstancesLen()
	if afterClose != before {
		t.Fatalf("gdInstances leaked %d entries after closing every gd this wiring created (afterClose delta=%d, want 0) — TokenResilienceManager's own GracefulDegradation was never closed", afterClose-before, afterClose-before)
	}

	// Only assert the shared health-check task itself stopped when this test
	// is known to be the sole registrant (before==0): the task is a
	// process-global singleton shared by every GracefulDegradation created
	// anywhere in the suite, so this assertion would be flaky under a
	// nonzero baseline left by another test.
	if before == 0 && GetResourceManager().IsTaskRunning("graceful-degradation-health-check") {
		t.Fatal("graceful-degradation-health-check task must stop once gdInstances is empty (last-instance stop gate)")
	}
}

// TestFix18_TraefikOidcCloseEmptiesGDInstances pins the FIX-18 major-finding
// gap left by the test above: calling erm.Close()/trm.Close() directly stays
// green even if the real (*TraefikOidc).Close() is reverted to skip one of
// them (utilities.go's t.errorRecoveryManager.Close() /
// t.tokenResilienceManager.Close() calls). This test wires both managers on
// a TraefikOidc exactly as NewWithContext does (main.go's
// t.errorRecoveryManager = NewErrorRecoveryManager(...) followed by
// t.tokenResilienceManager = NewTokenResilienceManager(...)) and drives the
// real Close(), so it only passes when Close() actually reaches both.
func TestFix18_TraefikOidcCloseEmptiesGDInstances(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	before := gdInstancesLen()

	oidc := &TraefikOidc{logger: logger}
	oidc.errorRecoveryManager = NewErrorRecoveryManager(logger)
	oidc.tokenResilienceManager = NewTokenResilienceManager(DefaultTokenResilienceConfig(), logger)

	afterNew := gdInstancesLen()
	if afterNew != before+2 {
		t.Fatalf("precondition: wiring one plugin instance must create exactly 2 GracefulDegradation instances; got delta %d", afterNew-before)
	}

	waitForHealthRoutineSettled(t, oidc.errorRecoveryManager.gracefulDegradation)
	waitForHealthRoutineSettled(t, oidc.tokenResilienceManager.errorRecoveryManager.gracefulDegradation)

	// Balance Close()'s own unregisterLiveInstance() call: New() always
	// registers before it returns an instance for Close() to eventually
	// unregister, and this test's synthetic instance must too, or it skews
	// the process-global liveInstanceCount permanently negative for every
	// other test that runs afterward in the same binary (FIX-35 territory,
	// but liveInstanceCount is shared package state regardless of which
	// finding a given test targets).
	registerLiveInstance()

	if err := oidc.Close(); err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}

	after := gdInstancesLen()
	if after != before {
		t.Fatalf("gdInstances leaked %d entries after TraefikOidc.Close (delta=%d, want 0) — Close must close both t.errorRecoveryManager and t.tokenResilienceManager", after-before, after-before)
	}
}

// TestFix18_CloseImmediatelyAfterNewDoesNotReRegister pins the exact race the
// FIX-18 review's scratch probe found: NewGracefulDegradation followed
// immediately by Close(), before the async health-check goroutine has had a
// chance to run. The old startHealthCheckRoutine re-added gd to gdInstances
// from inside that goroutine (after Close had already deleted it), permanently
// re-registering an already-closed instance and restarting the shared
// health-check task for it with nothing left able to ever stop it again.
func TestFix18_CloseImmediatelyAfterNewDoesNotReRegister(t *testing.T) {
	t.Cleanup(snapshotAndClearGdInstancesForTest())

	cfg := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(cfg, GetSingletonNoOpLogger())
	gd.Close()

	// Give the async health-check goroutine every opportunity to run and,
	// under the bug, re-register the closed instance.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		gdInstances.RLock()
		n := len(gdInstances.set)
		gdInstances.RUnlock()
		if n != 0 {
			t.Fatalf("closed instance was re-registered: gdInstances has %d entries, want 0", n)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestFix18_NewWithContextClosesManagersOnEarlyError pins the FIX-18 minor
// finding: NewWithContext creates t.errorRecoveryManager and
// t.tokenResilienceManager, then returns an error from a later validation
// step (here, an invalid private_key_jwt key) without ever closing either
// one — leaking their GracefulDegradation instances in gdInstances forever.
func TestFix18_NewWithContextClosesManagersOnEarlyError(t *testing.T) {
	before := gdInstancesLen()

	cfg := &Config{
		ProviderURL:               "https://accounts.google.com",
		ClientID:                  "test-client",
		ClientSecret:              "test-secret",
		CallbackURL:               "/callback",
		SessionEncryptionKey:      "this-is-a-valid-session-key-32b!",
		RateLimit:                 100,
		ClientAuthMethod:          "private_key_jwt",
		ClientAssertionKeyID:      "test-kid",
		ClientAssertionPrivateKey: "-----BEGIN PRIVATE KEY-----\nnot-valid-base64-content!!!\n-----END PRIVATE KEY-----\n",
	}

	plugin, err := NewWithContext(context.Background(), cfg, nil, "fix18-bad-key")
	if err == nil {
		if plugin != nil {
			plugin.Close()
		}
		t.Fatal("expected NewWithContext to fail on an invalid private_key_jwt key")
	}
	if plugin != nil {
		t.Fatal("NewWithContext must return a nil instance on error")
	}

	after := gdInstancesLen()
	if after != before {
		t.Fatalf("NewWithContext's error path leaked %d GracefulDegradation instance(s) in gdInstances (before=%d after=%d) — the errorRecoveryManager and tokenResilienceManager created just before the failure were never closed", after-before, before, after)
	}
}

// waitForHealthRoutineSettled polls until gd's async startHealthCheckRoutine
// goroutine has settled (see GracefulDegradation.healthRoutineSettled).
func waitForHealthRoutineSettled(t *testing.T, gd *GracefulDegradation) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if gd.healthRoutineSettled() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("health-check goroutine did not settle (task assigned or instance already closed) in time")
}

// gdInstancesLen reads the current size of the package-level gdInstances set
// under its own lock.
func gdInstancesLen() int {
	gdInstances.RLock()
	defer gdInstances.RUnlock()
	return len(gdInstances.set)
}

// snapshotAndClearGdInstancesForTest captures the current contents of the
// package-level gdInstances registry and replaces it with a fresh empty set,
// mirroring resetGdInstancesForTest (review_r34_regression_test.go). Unlike
// that helper, it returns a restore func the caller registers with
// t.Cleanup: a bare reset with no restore permanently discards whatever
// GracefulDegradation instances other tests in the same binary had
// registered before this test ran, instead of only clearing for the
// duration of this test.
func snapshotAndClearGdInstancesForTest() func() {
	gdInstances.Lock()
	saved := gdInstances.set
	gdInstances.set = make(map[*GracefulDegradation]struct{})
	gdInstances.Unlock()

	return func() {
		gdInstances.Lock()
		gdInstances.set = saved
		gdInstances.Unlock()
	}
}
