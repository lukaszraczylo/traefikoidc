package traefikoidc

import (
	"testing"
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

// gdInstancesLen reads the current size of the package-level gdInstances set
// under its own lock.
func gdInstancesLen() int {
	gdInstances.RLock()
	defer gdInstances.RUnlock()
	return len(gdInstances.set)
}
