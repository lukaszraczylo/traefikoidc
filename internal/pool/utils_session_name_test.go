package pool

import "testing"

// TestBuildSessionNameIndexes pins the gosec G115 fix: the single-digit fast
// path used rune('0'+index) for any index below 10, so a negative index
// produced a non-digit (index -1 gave "base_/"). The fast path now covers only
// 0..9, and other values use intToString.
func TestBuildSessionNameIndexes(t *testing.T) {
	cases := map[int]string{0: "base_0", 3: "base_3", 9: "base_9", 10: "base_10", 42: "base_42", -1: "base_-1", -7: "base_-7"}
	for index, want := range cases {
		if got := BuildSessionName("base", index); got != want {
			t.Errorf("BuildSessionName(%q, %d) = %q, want %q", "base", index, got, want)
		}
	}
}
