package traefikoidc

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pluginVersion is bumped manually on each release. Keep in sync with the
// most recent git tag (see `git tag --sort=-v:refname | head -1`).
const pluginVersion = "1.0.11"

const (
	telemetryProject = "traefikoidc"
	telemetryTimeout = 2 * time.Second
)

// telemetryEndpoint is intentionally a var rather than a const so the test
// suite in this package can retarget it at an httptest server. Production
// code never mutates it.
var telemetryEndpoint = "https://oss.raczylo.com/v1/ping"

// telemetryOnce guarantees a single anonymous "plugin loaded" ping per
// process lifetime. Traefik can instantiate a middleware many times per
// process (one per route using the plugin); the sync.Once gate keeps the
// fire-and-forget call from amplifying into many pings.
//
// Reset in tests via `telemetryOnce = sync.Once{}`.
var telemetryOnce sync.Once

// telemetryInflight tracks any background goroutine started by sendTelemetry.
// Tests Wait on it to drain in-flight goroutines before mutating package
// state. Production code never calls Wait — the goroutine is fire-and-forget.
var telemetryInflight sync.WaitGroup

// sendTelemetry fires one anonymous usage ping in the background. It is
// failproof by contract:
//
//   - never blocks the caller
//   - never panics (the goroutine recovers internally)
//   - never returns errors
//   - silently dropped on invalid input, env-driven opt-out, or network failure
//
// Opt-out is honored via any of:
//
//   - DO_NOT_TRACK=1
//   - OSS_TELEMETRY_DISABLED=1
//   - TRAEFIKOIDC_DISABLE_TELEMETRY=1
//
// Yaegi note: this file deliberately avoids generics (atomic.Pointer[T]) and
// range-over-int (Go 1.22) so it interprets under any reasonably recent
// Traefik yaegi runtime.
func sendTelemetry(version string) {
	telemetryOnce.Do(func() {
		if telemetryDisabledByEnv() {
			return
		}
		if !validTelemetryVersion(version) {
			return
		}
		telemetryInflight.Add(1)
		go func() {
			defer telemetryInflight.Done()
			defer func() { _ = recover() }()
			doTelemetryPost(version)
		}()
	})
}

func telemetryDisabledByEnv() bool {
	keys := []string{
		"DO_NOT_TRACK",
		"OSS_TELEMETRY_DISABLED",
		"TRAEFIKOIDC_DISABLE_TELEMETRY",
	}
	for _, k := range keys {
		v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
		if v == "1" || v == "true" || v == "yes" || v == "on" {
			return true
		}
	}
	return false
}

// validTelemetryVersion mirrors the server-side regex ^[A-Za-z0-9.+_-]{1,32}$
// using a byte loop. No allocation, no regexp dependency.
//
// Yaegi note: written as an `||` chain rather than `switch{case A,B,C:}` —
// some yaegi releases mis-evaluate comma-separated case expressions in
// switch-true blocks, returning false for all inputs.
func validTelemetryVersion(v string) bool {
	if len(v) == 0 || len(v) > 32 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '+' || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// doTelemetryPost builds the JSON body manually. The project name is a
// constant and the version is pre-validated against an ASCII-only allowlist,
// so direct concatenation needs no JSON escaping.
func doTelemetryPost(version string) {
	body := make([]byte, 0, 96)
	body = append(body, `{"project":"`...)
	body = append(body, telemetryProject...)
	body = append(body, `","version":"`...)
	body = append(body, version...)
	body = append(body, `","ts":`...)
	body = strconv.AppendInt(body, time.Now().Unix(), 10)
	body = append(body, '}')

	ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
	defer cancel()

	url := telemetryEndpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: telemetryTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}
