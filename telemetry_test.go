package traefikoidc

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// resetTelemetryState restores package-level mutable state so tests do not
// contaminate one another. The cleanup waits for any in-flight ping goroutine
// to finish before restoring telemetryEndpoint — without that drain step the
// goroutine and the cleanup would race on the var.
func resetTelemetryState(t *testing.T) {
	t.Helper()
	telemetryOnce = sync.Once{}
	prev := telemetryEndpoint
	t.Cleanup(func() {
		telemetryInflight.Wait()
		telemetryEndpoint = prev
		telemetryOnce = sync.Once{}
	})
}

func newTelemetryServer(t *testing.T, status int) (hits *int32, lastBody func() string) {
	t.Helper()
	var counter int32
	var mu sync.Mutex
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&counter, 1)
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		mu.Lock()
		body = string(b)
		mu.Unlock()
		w.WriteHeader(status)
	}))
	telemetryEndpoint = srv.URL
	t.Cleanup(srv.Close)
	return &counter, func() string {
		mu.Lock()
		defer mu.Unlock()
		return body
	}
}

func TestValidTelemetryVersion(t *testing.T) {
	good := []string{"1.2.3", "1.4.0-beta1", "2.0", "v1.0.0", "1.0.0+meta", "dev"}
	for _, v := range good {
		if !validTelemetryVersion(v) {
			t.Errorf("validTelemetryVersion(%q) = false, want true", v)
		}
	}
	bad := []string{"", "has space", "semi;colon", strings.Repeat("1", 33)}
	for _, v := range bad {
		if validTelemetryVersion(v) {
			t.Errorf("validTelemetryVersion(%q) = true, want false", v)
		}
	}
}

func TestTelemetryDisabledByEnv(t *testing.T) {
	for _, k := range []string{"DO_NOT_TRACK", "OSS_TELEMETRY_DISABLED", "TRAEFIKOIDC_DISABLE_TELEMETRY"} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, "1")
			if !telemetryDisabledByEnv() {
				t.Fatalf("%s=1 should disable", k)
			}
		})
	}
	t.Run("falsy_values_do_not_disable", func(t *testing.T) {
		t.Setenv("DO_NOT_TRACK", "0")
		t.Setenv("OSS_TELEMETRY_DISABLED", "false")
		t.Setenv("TRAEFIKOIDC_DISABLE_TELEMETRY", "no")
		if telemetryDisabledByEnv() {
			t.Fatal("falsy env values should not disable")
		}
	})
}

func TestSendTelemetry_FiresOnceAcrossManyCalls(t *testing.T) {
	resetTelemetryState(t)
	hits, lastBody := newTelemetryServer(t, http.StatusNoContent)

	for i := 0; i < 50; i++ {
		sendTelemetry("1.2.3")
	}
	telemetryInflight.Wait()

	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("expected exactly 1 hit, got %d", got)
	}

	var payload struct {
		Project string `json:"project"`
		Version string `json:"version"`
		Ts      int64  `json:"ts"`
	}
	if err := json.Unmarshal([]byte(lastBody()), &payload); err != nil {
		t.Fatalf("server received non-JSON body: %q (err: %v)", lastBody(), err)
	}
	if payload.Project != "traefikoidc" || payload.Version != "1.2.3" || payload.Ts <= 0 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestSendTelemetry_RespectsDisableEnv(t *testing.T) {
	resetTelemetryState(t)
	hits, _ := newTelemetryServer(t, http.StatusNoContent)
	t.Setenv("DO_NOT_TRACK", "1")

	sendTelemetry("1.2.3")
	telemetryInflight.Wait()

	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("DO_NOT_TRACK should suppress; got %d hits", got)
	}
}

func TestSendTelemetry_DropsInvalidVersion(t *testing.T) {
	resetTelemetryState(t)
	hits, _ := newTelemetryServer(t, http.StatusNoContent)

	sendTelemetry("has space")
	telemetryInflight.Wait()

	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("invalid version should suppress; got %d hits", got)
	}
}

func TestSendTelemetry_DoesNotBlock(t *testing.T) {
	resetTelemetryState(t)
	// Hanging server proves the caller is never blocked. The 2s context
	// timeout in doTelemetryPost ensures the goroutine eventually exits;
	// resetTelemetryState's cleanup waits for that drain before restoring
	// telemetryEndpoint so there is no race with this test's mutation.
	hung := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	t.Cleanup(hung.Close)
	telemetryEndpoint = hung.URL

	start := time.Now()
	sendTelemetry("1.2.3")
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("sendTelemetry blocked for %v, expected near-instant return", elapsed)
	}
}

func TestSendTelemetry_SurvivesServerError(t *testing.T) {
	resetTelemetryState(t)
	hits, _ := newTelemetryServer(t, http.StatusInternalServerError)

	sendTelemetry("1.2.3")
	telemetryInflight.Wait()

	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("request should still reach server even on 500; got %d hits", got)
	}
}
