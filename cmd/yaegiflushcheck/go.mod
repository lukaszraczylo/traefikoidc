module github.com/lukaszraczylo/traefikoidc/cmd/yaegiflushcheck

go 1.27.1

// main.go carries a `//go:build ignore` tag (see that file for why), so
// `go mod tidy` sees zero buildable packages here and removes this
// requirement instead of marking it direct. Do not run `go mod tidy` in
// this directory; edit the version by hand or via `go get` alone instead.
require github.com/traefik/yaegi v0.16.1
