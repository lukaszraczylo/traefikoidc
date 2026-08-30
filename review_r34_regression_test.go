package traefikoidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestFetchJWKSOversizeResponse: a provider JWKS larger than 1 MiB must be
// rejected explicitly, not silently truncated (which could yield a partial
// keyset and a spurious "no matching public key for kid").
func TestFetchJWKSOversizeResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Body strictly larger than the 1 MiB read limit (prefixed with a
		// valid JSON opener so the ONLY reason to reject is the size guard).
		body := `{"keys":[` + strings.Repeat("{}", (1<<20)/2) + `]}`
		w.Write([]byte(body))
	}))
	defer server.Close()

	cache := NewJWKCache()
	jwks, err := cache.GetJWKS(context.Background(), server.URL, http.DefaultClient)
	require.Error(t, err, "oversized JWKS must be rejected")
	require.Nil(t, jwks)
	require.Contains(t, err.Error(), "1 MiB")
}

func waitForHealthTaskRunning(t *testing.T, want bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if GetResourceManager().IsTaskRunning("graceful-degradation-health-check") == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("health task running state != %v", want)
}

func waitForGdInstances(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		gdInstances.RLock()
		n := len(gdInstances.set)
		gdInstances.RUnlock()
		if n >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	gdInstances.RLock()
	n := len(gdInstances.set)
	gdInstances.RUnlock()
	t.Fatalf("gd instances wanted %d got %d", want, n)
}

// resetGdInstancesForTest establishes a clean baseline for the process-global
// instance registry so a test's "last instance" and iteration assertions are
// not skewed by instances created by earlier tests in the same process.
func resetGdInstancesForTest() {
	gdInstances.Lock()
	gdInstances.set = make(map[*GracefulDegradation]struct{})
	gdInstances.Unlock()
}

// TestConfigKeySeparatesBehaviorDifferingConfigs: two configs that differ only
// in a transport-behavior field (here DisableCompression) must get distinct
// transports, not share one built with the first config's settings.
func TestConfigKeySeparatesBehaviorDifferingConfigs(t *testing.T) {
	pool := &SharedTransportPool{
		transports:  make(map[string]*sharedTransport),
		maxConns:    20,
		maxClients:  5,
		clientCount: 0,
		ctx:         context.Background(),
	}

	a := DefaultHTTPClientConfig()
	b := a
	b.DisableCompression = !a.DisableCompression

	require.NotEqual(t, pool.configKey(a), pool.configKey(b),
		"configs differing only in DisableCompression must have distinct keys")

	ta := pool.GetOrCreateTransport(a)
	tb := pool.GetOrCreateTransport(b)
	require.NotEqual(t, ta, tb, "behaviorally different configs must not share a transport")

	// Same config still reuses its transport.
	ta2 := pool.GetOrCreateTransport(a)
	require.Equal(t, ta, ta2, "identical config reuses its transport")
}

// TestRegisterBackgroundTaskRestartsAfterStop: a singleton task stopped on a
// close+recreate cycle must be restartable on re-registration (Start is
// once-guarded, so the registry must replace a stopped task with a fresh one).
func TestRegisterBackgroundTaskRestartsAfterStop(t *testing.T) {
	rm := &ResourceManager{
		tasks:  map[string]*BackgroundTask{},
		logger: GetSingletonNoOpLogger(),
	}
	const name = "restart-test-task"
	var calls int32
	register := func() {
		t.Helper()
		require.NoError(t, rm.RegisterBackgroundTask(name, time.Hour, func() {
			atomic.AddInt32(&calls, 1)
		}))
	}

	register()
	require.NoError(t, rm.StartBackgroundTask(name))
	require.True(t, rm.IsTaskRunning(name))

	require.NoError(t, rm.StopBackgroundTask(name))
	require.False(t, rm.IsTaskRunning(name))

	// Re-register after stop: must be restartable (fresh BackgroundTask).
	register()
	require.NoError(t, rm.StartBackgroundTask(name))
	require.True(t, rm.IsTaskRunning(name), "re-registered singleton task must be restartable after stop")

	require.NoError(t, rm.StopBackgroundTask(name))
}

func TestSharedHealthTaskSurvivesOtherInstanceClose(t *testing.T) {
	resetGdInstancesForTest()

	cfg := DefaultGracefulDegradationConfig()
	cfg.HealthCheckInterval = time.Hour // keep the task from churning

	gd1 := NewGracefulDegradation(cfg, GetSingletonNoOpLogger())
	gd2 := NewGracefulDegradation(cfg, GetSingletonNoOpLogger())
	defer gd2.Close()

	waitForHealthTaskRunning(t, true)
	waitForGdInstances(t, 2)

	gd1.Close()
	waitForHealthTaskRunning(t, true)

	gd2.Close()
	waitForHealthTaskRunning(t, false)
}

// TestSharedHealthTaskReachesAllInstances: the shared health task must exercise
// health checks registered on ANY live instance, not just the first one.
func TestSharedHealthTaskReachesAllInstances(t *testing.T) {
	resetGdInstancesForTest()

	cfg := DefaultGracefulDegradationConfig()
	cfg.HealthCheckInterval = time.Hour

	gd1 := NewGracefulDegradation(cfg, GetSingletonNoOpLogger())
	gd2 := NewGracefulDegradation(cfg, GetSingletonNoOpLogger())
	defer gd1.Close()
	defer gd2.Close()

	waitForGdInstances(t, 2)
	waitForHealthTaskRunning(t, true)

	var called atomic.Bool
	gd2.RegisterHealthCheck("svc-on-instance-2", func() bool {
		called.Store(true)
		return true
	})

	globalPerformHealthChecks()
	require.True(t, called.Load(),
		"a health check registered on the second instance must be exercised by the shared task")
}

// TestRecordL2Error not here: lives in internal/cache/backends (hybrid test).
