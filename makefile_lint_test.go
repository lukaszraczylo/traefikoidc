package traefikoidc

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestMakeLintPropagatesGolangciLintResult pins NEW-02. The old lint recipe,
// `golangci-lint run ./... || echo "golangci-lint not installed; skipping"`,
// turned every lint failure into exit 0, so `make lint` and the review
// preflight always reported success. The target must now fail when
// golangci-lint fails, pass when it passes, and still skip with exit 0 when
// golangci-lint is not installed. A fake golangci-lint on PATH stands in for
// the real one.
func TestMakeLintPropagatesGolangciLintResult(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the lint recipe needs a POSIX shell")
	}
	makeBin, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make is not installed")
	}

	runLint := func(t *testing.T, fakeExitCode string) (string, error) {
		t.Helper()
		dir := t.TempDir()
		if fakeExitCode != "" {
			script := "#!/bin/sh\nexit " + fakeExitCode + "\n"
			if err := os.WriteFile(filepath.Join(dir, "golangci-lint"), []byte(script), 0o755); err != nil {
				t.Fatalf("write fake golangci-lint: %v", err)
			}
		}
		env := make([]string, 0, len(os.Environ())+1)
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "PATH=") {
				env = append(env, kv)
			}
		}
		env = append(env, "PATH="+dir)
		// GO=true keeps the Makefile's `$(shell $(GO) env GOPATH)` from
		// needing a real go binary on the restricted PATH.
		cmd := exec.Command(makeBin, "-s", "GO=true", "lint")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	t.Run("lint findings fail the target", func(t *testing.T) {
		if out, err := runLint(t, "1"); err == nil {
			t.Fatalf("make lint exited 0 although golangci-lint failed; output: %q", out)
		}
	})
	t.Run("clean lint passes", func(t *testing.T) {
		if out, err := runLint(t, "0"); err != nil {
			t.Fatalf("make lint failed although golangci-lint passed: %v; output: %q", err, out)
		}
	})
	t.Run("missing golangci-lint skips", func(t *testing.T) {
		out, err := runLint(t, "")
		if err != nil {
			t.Fatalf("make lint failed although golangci-lint is not installed: %v; output: %q", err, out)
		}
		if !strings.Contains(out, "skipping") {
			t.Fatalf("make lint did not report the skip; output: %q", out)
		}
	})
}
