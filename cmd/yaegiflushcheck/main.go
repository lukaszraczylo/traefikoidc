// Command yaegiflushcheck drives the real plugin under yaegi with a
// COMPILED next handler that calls http.NewResponseController(w).Flush(),
// reproducing the FIX-06 finding end to end: cmd/yaegicheck (in the root
// module) only proves the package imports and New() succeeds under yaegi
// (import-time surface); this probe additionally proves that a request
// routed through the interpreted ServeHTTP and forwarded to a compiled
// downstream handler hands that handler a writer that still supports Flush
// -- the concrete SSE-in-production failure the finding describes.
//
// This program is its own nested Go module (this directory has its own
// go.mod) rather than living in the root module: it needs
// github.com/traefik/yaegi/interp and .../stdlib compiled in, and the root
// module deliberately does not depend on yaegi (only uses it as an external
// CLI tool, see Makefile). A nested module never enters the root module's
// `go build ./...` / `go vet ./...` / `go test ./...` / vendor graph.
//
// It works by having yaegi interpret a small BuildHandler wrapper (source
// below) that calls the real oidc.CreateConfig/oidc.New, so all
// interpreted-type manipulation (the *oidc.Config struct) happens inside
// the interpreter; the only values crossing the interpreted/compiled
// boundary are the compiled `next` handler going in and the resulting
// http.Handler coming out, both of which are the same crossings Traefik's
// runtime performs when it loads a plugin.
//
// Prerequisite: GOPATH must have src/github.com/lukaszraczylo/traefikoidc
// symlinked (or copied) to the checkout under test -- yaegi resolves the
// "github.com/lukaszraczylo/traefikoidc" import through GOPATH, not through
// the root module's go.mod (see FIX-06, middleware.go).
//
// Run with (from this directory):
//
//	GOPATH=<tmp-gopath-with-the-symlink> DO_NOT_TRACK=1 go run .
//
// Exits non-zero, printing FAIL, on any error including a non-nil Flush
// error. Prints OK and exits 0 on success.
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

const buildHandlerSource = `
package probe

import (
	"context"
	"net/http"

	oidc "github.com/lukaszraczylo/traefikoidc"
)

func BuildHandler(next http.Handler) (http.Handler, error) {
	cfg := oidc.CreateConfig()
	cfg.ProviderURL = "https://accounts.google.com"
	cfg.ClientID = "yaegi-flush-check-client"
	cfg.ClientSecret = "yaegi-flush-check-secret"
	cfg.CallbackURL = "/oauth2/callback"
	cfg.SessionEncryptionKey = "0123456789abcdef0123456789abcdef"
	cfg.RateLimit = 100
	// Exclude every path so ServeHTTP takes the excluded-URL bypass
	// (shouldBypassAuth), which forwards to next unconditionally and
	// without waiting on OIDC provider discovery.
	cfg.ExcludedURLs = []string{"/"}
	return oidc.New(context.Background(), next, cfg, "yaegi-flush-check")
}
`

func fail(format string, args ...any) {
	fmt.Printf("FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	i := interp.New(interp.Options{GoPath: os.Getenv("GOPATH")})
	if err := i.Use(stdlib.Symbols); err != nil {
		fail("register stdlib symbols: %v", err)
	}

	if _, err := i.Eval(buildHandlerSource); err != nil {
		fail("evaluate BuildHandler source under yaegi: %v", err)
	}

	buildHandlerV, err := i.Eval("probe.BuildHandler")
	if err != nil {
		fail("resolve probe.BuildHandler: %v", err)
	}

	var flushErr error
	var flushErrSet bool
	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		flushErr = http.NewResponseController(w).Flush()
		flushErrSet = true
	})

	rets := buildHandlerV.Call([]reflect.Value{reflect.ValueOf(http.Handler(next))})
	if errV := rets[1]; !errV.IsNil() {
		fail("New returned an error under yaegi: %v", errV.Interface())
	}

	handler, ok := rets[0].Interface().(http.Handler)
	if !ok {
		fail("BuildHandler's return value does not satisfy http.Handler from compiled code")
	}

	srv := httptest.NewServer(handler)
	defer srv.Close()

	getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		fail("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		fail("GET %s: %v", srv.URL+"/", err)
	}
	defer resp.Body.Close()

	if !nextCalled {
		fail("next handler was never reached (status=%d)", resp.StatusCode)
	}
	if !flushErrSet {
		fail("next handler ran but never recorded a Flush result")
	}
	if flushErr != nil {
		fail("compiled next's http.NewResponseController(w).Flush() returned an error through the interpreted plugin: %v", flushErr)
	}

	fmt.Println("OK: compiled next's http.NewResponseController(w).Flush() succeeded through the interpreted plugin under yaegi")
}
