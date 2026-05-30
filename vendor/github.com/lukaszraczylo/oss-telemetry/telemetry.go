// Package telemetry sends anonymous usage pings for open-source Go projects.
//
// Wire format (POST application/json):
//
//	{"project":"<name>","version":"<ver>","ts":<unix-seconds>}
//
// Design contract (failproof):
//   - never blocks the caller (work happens in a goroutine)
//   - never panics (background goroutine recovers internally)
//   - never returns errors (silently no-ops on bad input or network failure)
//   - never retries, never deduplicates, never persists state — the client
//     fires a single ping and forgets; the server is responsible for
//     deduplication, abuse protection, and aggregation
//
// Typical usage at program startup:
//
//	telemetry.Send("my-tool", "1.2.3")
//
// For short-lived CLI processes that may exit before the goroutine finishes:
//
//	telemetry.Send("my-tool", "1.2.3")
//	defer telemetry.Wait(2 * time.Second)
//
// Disablement (any one of these suppresses pings):
//   - environment variable DO_NOT_TRACK=1
//   - environment variable OSS_TELEMETRY_DISABLED=1
//   - environment variable <UPPER_PROJECT>_DISABLE_TELEMETRY=1
//     (project name uppercased, dashes replaced with underscores)
//   - calling telemetry.Disable() at runtime
package telemetry

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultEndpoint = "https://oss.raczylo.com/v1/ping"
	httpTimeout     = 2 * time.Second
	maxProjectLen   = 64
	maxVersionLen   = 32
)

// Yaegi note: this package is consumed by the traefikoidc Traefik plugin, which
// Traefik interprets with Yaegi (it vendors and interprets dependency source).
// It therefore avoids generic stdlib types (atomic.Pointer[T], atomic.Bool) and
// range-over-int (Go 1.22), which some Traefik/Yaegi runtimes cannot interpret.
// Endpoint mutation uses a mutex-guarded string; the disabled flag uses the
// function-based sync/atomic int32 API (atomic.LoadInt32/StoreInt32).
var (
	// endpointURL holds the ingest URL. Production code never mutates it; the
	// setter exists only so the test suite can retarget it at httptest servers
	// while goroutines started by Send are still in flight.
	endpointMu  sync.RWMutex
	endpointURL = defaultEndpoint

	disabled int32 // 0 = enabled, 1 = disabled; accessed via sync/atomic only
	inflight sync.WaitGroup

	client = &http.Client{Timeout: httpTimeout}
)

func currentEndpoint() string {
	endpointMu.RLock()
	defer endpointMu.RUnlock()
	return endpointURL
}

func setEndpointURL(u string) {
	endpointMu.Lock()
	endpointURL = u
	endpointMu.Unlock()
}

// Send fires a single anonymous telemetry ping in the background and returns
// immediately. It never blocks, never panics, and never reports errors.
// Invalid inputs, disabled state, and network failures are silently dropped.
//
// Version strings are validated against a SemVer-ish shape that mirrors the
// receiver. An optional leading "v" or "V" is accepted and stripped before
// transmission so that callers can pass either "v1.2.3" or "1.2.3"; the
// wire form is always the unprefixed canonical version.
//
// Call once at program startup. Calling repeatedly will send repeated pings;
// the server is responsible for deduplication.
func Send(project, version string) {
	if atomic.LoadInt32(&disabled) != 0 {
		return
	}
	if isDisabledByEnv(project) {
		return
	}
	if !validProject(project) || !validVersion(version) {
		return
	}
	canonical := normalizeVersion(version)

	inflight.Add(1)
	go func() {
		defer inflight.Done()
		defer func() { _ = recover() }()
		dispatch(project, canonical)
	}()
}

// SendForModule is the recommended call form for Go libraries: it resolves
// the version automatically from Go's build info for the given module path
// so consumers do not need to maintain a hand-bumped version constant in
// source. Behaviour and contract are otherwise identical to [Send].
//
// Resolution order:
//
//  1. debug.ReadBuildInfo Deps entry for modulePath (authoritative when the
//     library is consumed via go.mod);
//  2. debug.ReadBuildInfo Main when the library is itself the main module
//     (e.g. running its own tests or examples);
//  3. fallback parameter, used only when build info is unavailable or
//     unhelpful (replace directives, detached `go run`, ldflag override).
//
// Any leading "v" reported by build info is stripped to match the canonical
// wire form. Empty / "(devel)" build versions are skipped in favour of the
// next resolution source. Typical usage:
//
//	telemetry.SendForModule("my-tool", "github.com/me/my-tool", "0.0.0-dev")
func SendForModule(project, modulePath, fallback string) {
	Send(project, ResolveModuleVersion(modulePath, fallback))
}

// ResolveModuleVersion implements the version resolution used by
// SendForModule. Exposed for callers that need to format the resolved
// version (e.g. logging) without firing a ping.
func ResolveModuleVersion(modulePath, fallback string) string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, d := range info.Deps {
			if d != nil && d.Path == modulePath && isUsableBuildVersion(d.Version) {
				return strings.TrimPrefix(d.Version, "v")
			}
		}
		if info.Main.Path == modulePath && isUsableBuildVersion(info.Main.Version) {
			return strings.TrimPrefix(info.Main.Version, "v")
		}
	}
	return fallback
}

func isUsableBuildVersion(v string) bool {
	return v != "" && v != "(devel)"
}

// Disable suppresses all subsequent Send calls in this process.
// Idempotent and safe to call from any goroutine.
func Disable() {
	atomic.StoreInt32(&disabled, 1)
}

// Wait blocks until all in-flight pings have completed, or until timeout
// elapses — whichever comes first. Useful for short-lived CLI processes
// that may otherwise exit before the background goroutine finishes its POST.
//
// A non-positive timeout returns immediately.
func Wait(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	done := make(chan struct{})
	go func() {
		inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

func dispatch(project, version string) {
	body := buildPayload(project, version, time.Now().Unix())

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, currentEndpoint(), bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// buildPayload writes the JSON body without encoding/json. The validators
// restrict project and version to characters that never require JSON
// escaping, so direct concatenation is safe.
func buildPayload(project, version string, ts int64) []byte {
	// Wrapper text plus 20 chars for a signed int64.
	const overhead = len(`{"project":"","version":"","ts":}`) + 20
	buf := make([]byte, 0, len(project)+len(version)+overhead)
	buf = append(buf, `{"project":"`...)
	buf = append(buf, project...)
	buf = append(buf, `","version":"`...)
	buf = append(buf, version...)
	buf = append(buf, `","ts":`...)
	buf = strconv.AppendInt(buf, ts, 10)
	buf = append(buf, '}')
	return buf
}

func validProject(p string) bool {
	n := len(p)
	if n == 0 || n > maxProjectLen {
		return false
	}
	for i := 0; i < n; i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-':
		default:
			return false
		}
	}
	return true
}

// validVersion accepts SemVer-ish version strings with an optional leading
// "v"/"V" prefix. Acceptable shape (after stripping the leading v):
//
//	MAJOR[.MINOR[.PATCH]] ("-"prerelease)? ("+"build)?
//
// where MAJOR/MINOR/PATCH are ASCII digit sequences and the prerelease/build
// payloads are non-empty runs of [0-9A-Za-z.-]. This intentionally mirrors
// the receiver's version regex so junk like "dev" or "git-2026-05-22" never
// leaves the client (where it would only be rejected with HTTP 400 anyway).
func validVersion(v string) bool {
	n := len(v)
	if n == 0 || n > maxVersionLen {
		return false
	}
	if v[0] == 'v' || v[0] == 'V' {
		v = v[1:]
	}
	if len(v) == 0 {
		return false
	}
	return checkSemverShape(v)
}

// normalizeVersion strips an optional leading "v"/"V" so the on-the-wire
// version matches the form stored server-side by the version refresher cron
// (which also strips the leading v from release tags). Callers may pass
// either "v1.2.3" or "1.2.3" — only the unprefixed form is transmitted.
func normalizeVersion(v string) string {
	if len(v) > 0 && (v[0] == 'v' || v[0] == 'V') {
		return v[1:]
	}
	return v
}

func checkSemverShape(s string) bool {
	i := 0
	if !readDigitRun(s, &i) {
		return false
	}
	for groups := 0; groups < 2 && i < len(s) && s[i] == '.'; groups++ {
		i++
		if !readDigitRun(s, &i) {
			return false
		}
	}
	if i < len(s) && s[i] == '-' {
		i++
		if !readIdentRun(s, &i, '+') {
			return false
		}
	}
	if i < len(s) && s[i] == '+' {
		i++
		if !readIdentRun(s, &i, 0) {
			return false
		}
	}
	return i == len(s)
}

func readDigitRun(s string, i *int) bool {
	start := *i
	for *i < len(s) && s[*i] >= '0' && s[*i] <= '9' {
		*i++
	}
	return *i > start
}

// readIdentRun consumes [0-9A-Za-z.-] until end-of-string or until `stop`
// is hit (stop=0 disables the early-stop check). Returns false if no
// characters were consumed (i.e. empty payload).
func readIdentRun(s string, i *int, stop byte) bool {
	start := *i
	for *i < len(s) {
		c := s[*i]
		if stop != 0 && c == stop {
			break
		}
		valid := (c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			c == '.' || c == '-'
		if !valid {
			return false
		}
		*i++
	}
	return *i > start
}

func isDisabledByEnv(project string) bool {
	if truthy(os.Getenv("DO_NOT_TRACK")) {
		return true
	}
	if truthy(os.Getenv("OSS_TELEMETRY_DISABLED")) {
		return true
	}
	if project == "" {
		return false
	}
	key := projectEnvKey(project)
	return truthy(os.Getenv(key))
}

// projectEnvKey returns "<UPPER_PROJECT>_DISABLE_TELEMETRY" using a single
// allocation rather than chained strings.ToUpper(strings.ReplaceAll(...)).
func projectEnvKey(project string) string {
	const suffix = "_DISABLE_TELEMETRY"
	buf := make([]byte, 0, len(project)+len(suffix))
	for i := 0; i < len(project); i++ {
		c := project[i]
		switch {
		case c == '-':
			c = '_'
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		buf = append(buf, c)
	}
	buf = append(buf, suffix...)
	return string(buf)
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
