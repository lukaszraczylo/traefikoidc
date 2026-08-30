package resilience

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBackend is a minimal CacheBackend whose Ping can be toggled to fail,
// so HealthCheckBackend's status transition can be driven deterministically.
type fakeBackend struct {
	mu   sync.Mutex
	data map[string][]byte
	fail atomic.Bool
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{data: make(map[string][]byte)}
}

func (f *fakeBackend) Set(_ context.Context, key string, value []byte, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = value
	return nil
}

func (f *fakeBackend) Get(_ context.Context, key string) ([]byte, time.Duration, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	return v, 0, ok, nil
}

func (f *fakeBackend) Delete(_ context.Context, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.data[key]
	delete(f.data, key)
	return ok, nil
}

func (f *fakeBackend) Exists(_ context.Context, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.data[key]
	return ok, nil
}

func (f *fakeBackend) Clear(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data = make(map[string][]byte)
	return nil
}

func (f *fakeBackend) GetStats() map[string]interface{} { return map[string]interface{}{} }

func (f *fakeBackend) Close() error { return nil }

func (f *fakeBackend) Ping(_ context.Context) error {
	if f.fail.Load() {
		return errors.New("injected ping failure")
	}
	return nil
}

// TestHealthCheckBackendTransitions covers the previously 0%-covered
// HealthCheckBackend wrapper: optimistic start, eventual transition to
// unhealthy under backend failures, and recovery once the backend returns.
func TestHealthCheckBackendTransitions(t *testing.T) {
	bt := newFakeBackend()
	cfg := &HealthCheckConfig{
		CheckInterval:      5 * time.Millisecond,
		Timeout:            20 * time.Millisecond,
		HealthyThreshold:   1,
		UnhealthyThreshold: 2,
	}
	hc := NewHealthCheckBackend(bt, cfg).(*HealthCheckBackend)
	t.Cleanup(func() { _ = hc.Close() })

	// Optimistic start: healthy before any check runs.
	if !hc.IsHealthy() {
		t.Fatal("expected optimistic healthy start")
	}

	// Delegation: Set/Get pass through the wrapper to the backend.
	ctx := context.Background()
	if err := hc.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatalf("Set through wrapper: %v", err)
	}
	if got, _, ok, _ := hc.Get(ctx, "k"); !ok || string(got) != "v" {
		t.Fatalf("Get through wrapper returned ok=%v value=%q", ok, got)
	}

	// Fail the backend: the health loop must mark it unhealthy.
	bt.fail.Store(true)
	waitFor(t, 3*time.Second, "backend to become unhealthy", func() bool {
		return !hc.IsHealthy()
	})

	// Restore the backend: it must recover to healthy.
	bt.fail.Store(false)
	waitFor(t, 3*time.Second, "backend to recover", hc.IsHealthy)

	// Stats expose health state.
	if _, ok := hc.GetStats()["health"]; !ok {
		t.Fatal("expected health key in GetStats")
	}

	// Remaining delegation methods route through the wrapper cleanly.
	if ok, err := hc.Exists(ctx, "k"); err != nil || !ok {
		t.Fatalf("Exists through wrapper: ok=%v err=%v", ok, err)
	}
	if ok, err := hc.Delete(ctx, "k"); err != nil || !ok {
		t.Fatalf("Delete through wrapper: ok=%v err=%v", ok, err)
	}
	if err := hc.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatalf("Set for Clear: %v", err)
	}
	if err := hc.Clear(ctx); err != nil {
		t.Fatalf("Clear through wrapper: %v", err)
	}
	if err := hc.Ping(ctx); err != nil {
		t.Fatalf("Ping through wrapper: %v", err)
	}
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
