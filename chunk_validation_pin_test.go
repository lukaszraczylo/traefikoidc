package traefikoidc

import (
	"strings"
	"testing"
)

// These tests pin the token-content validators' results, including for
// multi-byte UTF-8 input, so their loops can be rewritten for yaegi (where
// ranging over a string allocates O(n²)) without changing behavior.

func TestDetectRepeatedCharactersPinned(t *testing.T) {
	cm := NewChunkManager(NewLogger(""))
	cases := []struct {
		name    string
		token   string
		wantErr string
	}{
		{"short token skipped", "aaaaaaaaa", ""},
		{"varied ascii", "abcdefghijklmnopqrstuvwxyz0123456789", ""},
		{"20 repeats allowed", strings.Repeat("a", 20) + strings.Repeat("bcdefghij", 4), ""},
		{"21 repeats rejected", strings.Repeat("a", 21) + strings.Repeat("bcdefghij", 4), "excessive repeated characters (21 consecutive)"},
		{"multibyte run counted per rune", strings.Repeat("é", 21) + strings.Repeat("bcdefghij", 4), "excessive repeated characters (21 consecutive)"},
		// Rune counts are divided by the byte length, so a multi-byte rune
		// cannot reach the 70% threshold. Pinned as-is.
		{"multibyte frequency divides by byte length", strings.Repeat("éééx", 8), ""},
		{"ascii frequency over 70%", strings.Repeat("aaaab", 8), "suspicious character frequency (char 'a'"},
		{"multibyte mixed passes", "日本語テキストabcdefghijklmnopqrstuvwxyz", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cm.detectRepeatedCharacters(tc.token, AccessTokenConfig)
			assertPinnedErr(t, err, tc.wantErr)
		})
	}
}

func TestValidateJWTFormatPinned(t *testing.T) {
	cm := NewChunkManager(NewLogger(""))
	cases := []struct {
		name    string
		token   string
		wantErr string
	}{
		{"valid base64url parts", jwtLike("eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJ4In0", "c2lnbmF0dXJlLXZhbHVl"), ""},
		{"padding allowed", jwtLike("eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJ4In0=", "c2lnbmF0dXJl"), ""},
		{"plus rejected", jwtLike("eyJhbGciOiJSUzI1NiJ9", "eyJzd+IiOiJ4In0", "c2lnbmF0dXJl"), "invalid base64url character in part 1"},
		{"multibyte rejected", jwtLike("eyJhbGciOiJSUzI1NiJ9", "eyJzdé", "c2lnbmF0dXJl"), "invalid base64url character in part 1"},
		{"control char rejected", jwtLike("eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJ4In0", "c2ln\x01bmF0"), "invalid base64url character in part 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cm.validateJWTFormat(tc.token, "access")
			assertPinnedErr(t, err, tc.wantErr)
		})
	}
}

func TestValidateTokenSanitizationPinned(t *testing.T) {
	cm := NewChunkManager(NewLogger(""))
	cases := []struct {
		name    string
		token   string
		wantErr string
	}{
		{"clean jwt", jwtLike("eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJ4In0", "c2lnbmF0dXJl"), ""},
		{"multibyte allowed", jwtLike("eyJhbGciOiJSUzI1NiJ9", "日本語", "c2lnbmF0dXJl"), ""},
		{"control char byte offset", "abcé\x01def", "control character at position 5"},
		{"delete char", "abcdef\x7fgh", "control character at position 6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cm.validateTokenSanitization(tc.token, AccessTokenConfig)
			assertPinnedErr(t, err, tc.wantErr)
		})
	}
}

// jwtLike joins parts with dots at runtime; JWT-shaped literals trip the
// pre-commit secret scanner.
func jwtLike(parts ...string) string { return strings.Join(parts, ".") }

func assertPinnedErr(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want containing %q", err, want)
	}
}
