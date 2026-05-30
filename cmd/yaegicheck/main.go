//go:build ignore

// Command yaegicheck verifies that the traefikoidc plugin can be imported and
// instantiated by the yaegi interpreter — the same way Traefik loads a plugin.
//
// It is run by `make yaegi-validate`. Importing the plugin package forces yaegi
// to interpret every source file in the package (and its vendored
// dependencies), so any construct yaegi cannot handle (unsupported stdlib
// symbol, reflection edge case, etc.) surfaces here rather than at Traefik load
// time. CreateConfig + New additionally exercise the instantiation path
// (session manager, cookie codec, caches, key derivation) under the interpreter.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	oidc "github.com/lukaszraczylo/traefikoidc"
)

func main() {
	cfg := oidc.CreateConfig()
	cfg.ProviderURL = "https://accounts.google.com"
	cfg.ClientID = "yaegi-check-client"
	cfg.ClientSecret = "yaegi-check-secret"
	cfg.CallbackURL = "/oauth2/callback"
	cfg.SessionEncryptionKey = "0123456789abcdef0123456789abcdef"
	cfg.RateLimit = 100

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h, err := oidc.New(context.Background(), next, cfg, "yaegi-check")
	if err != nil {
		fmt.Println("FAIL: New returned an error under yaegi:", err)
		os.Exit(1)
	}
	if h == nil {
		fmt.Println("FAIL: New returned a nil handler under yaegi")
		os.Exit(1)
	}
	if closer, ok := h.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	fmt.Println("OK: traefikoidc imported + CreateConfig + New succeeded under yaegi")
}
