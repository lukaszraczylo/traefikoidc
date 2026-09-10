package traefikoidc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRoundFilesDependOnlyOnSharedHelpers is a static regression pin for
// FIX-41 (see cache_test_helpers_test.go, jwt_test_helpers_test.go,
// logout_test_helpers_test.go, plugin_test_helpers_test.go): a non-Test /
// non-Benchmark / non-Fuzz helper function declared inside a
// review_rNN*_test.go "round" file must never be referenced from any other
// test file in the package, including another round file. Round files are
// individually renamed, folded together, or deleted as reviews get
// superseded; a helper another file silently depends on breaks that file the
// moment its declaring round file changes, with no compiler warning pointing
// at the real cause.
//
// Before the R4 re-review fix, this test failed on two counts:
//   - access_token_unexpired_iat_optional_test.go used makeTestJWT, declared
//     in review_r92_test.go.
//   - fix18_gd_lifecycle_test.go used resetGdInstancesForTest, declared in
//     review_r34_regression_test.go.
//
// Both helpers were moved into shared *_test_helpers_test.go files. This
// test fails again the moment a new file reintroduces the pattern.
func TestRoundFilesDependOnlyOnSharedHelpers(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	fset := token.NewFileSet()
	files := make(map[string]*ast.File)
	var testFiles []string

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files[name] = f
		testFiles = append(testFiles, name)
	}

	// Collect non-Test/Benchmark/Fuzz top-level funcs declared in round
	// files, keyed by name -> declaring file.
	declaredIn := map[string]string{}
	for _, name := range testFiles {
		if !strings.HasPrefix(name, "review_r") {
			continue
		}
		for _, decl := range files[name].Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			fname := fn.Name.Name
			if strings.HasPrefix(fname, "Test") || strings.HasPrefix(fname, "Benchmark") || strings.HasPrefix(fname, "Fuzz") {
				continue
			}
			declaredIn[fname] = name
		}
	}

	// Flag any identifier use of a round-declared helper from a file other
	// than the one that declares it.
	for _, name := range testFiles {
		ast.Inspect(files[name], func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			declFile, isRoundHelper := declaredIn[ident.Name]
			if isRoundHelper && declFile != name {
				t.Errorf("%s uses %s, a helper declared in round file %s — move %s into a shared *_test_helpers_test.go file (FIX-41)", name, ident.Name, declFile, ident.Name)
			}
			return true
		})
	}
}
