package backends

// contains reports whether s contains substr, case-insensitively. Used by
// RedisBackend's retry classification (redis.go) to match Redis error
// messages against known-retryable patterns.
//
// Hand-rolled instead of strings.Contains + strings.ToLower to avoid an
// allocation per call on the retry-check hot path.
func contains(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if toLower(s[i+j]) != toLower(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// toLower converts a byte to lowercase (ASCII only).
func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}
