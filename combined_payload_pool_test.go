package traefikoidc

import (
	"sync"
	"testing"
)

func TestDecompressCombinedPayloadReusesReaders(t *testing.T) {
	var readers sync.Pool
	first, err := compressCombinedPayload(&combinedSessionPayload{Ui: "first@example.com"})
	if err != nil {
		t.Fatalf("compress first: %v", err)
	}
	second, err := compressCombinedPayload(&combinedSessionPayload{Ui: "second@example.com"})
	if err != nil {
		t.Fatalf("compress second: %v", err)
	}

	cases := []struct {
		name     string
		input    string
		wantUser string
		wantErr  bool
	}{
		{"first payload", first, "first@example.com", false},
		{"corrupt payload rejected", "bm90LWd6aXA=", "", true},
		{"second payload after corrupt one", second, "second@example.com", false},
		{"first payload again", first, "first@example.com", false},
	}
	for _, tc := range cases {
		got, err := decompressCombinedPayload(tc.input, &readers)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%s: expected error", tc.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got.Ui != tc.wantUser {
			t.Fatalf("%s: user = %q, want %q", tc.name, got.Ui, tc.wantUser)
		}
	}
}
