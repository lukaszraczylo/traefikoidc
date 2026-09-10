package traefikoidc

// Shared GracefulDegradation-instance-registry test helper for
// round-regression and FIX-round tests.
//
// Moved here for the R4 re-review (closing the rest of FIX-41): resetGdInstancesForTest
// was declared inside review_r34_regression_test.go but consumed by
// fix18_gd_lifecycle_test.go, a FIX-round test file — the dependency was not
// even confined to other round files. Every review_rNN*_test.go and
// fixNN*_test.go file must depend only on shared helpers like this one,
// never on another round file's private declarations.

// resetGdInstancesForTest establishes a clean baseline for the process-global
// gdInstances registry so a test's "last instance" and iteration assertions
// are not skewed by instances created by earlier tests in the same process.
func resetGdInstancesForTest() {
	gdInstances.Lock()
	gdInstances.set = make(map[*GracefulDegradation]struct{})
	gdInstances.Unlock()
}
