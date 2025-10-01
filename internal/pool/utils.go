// Package pool provides centralized memory pool management utilities
package pool

import (
	"strings"
)

// BuildSessionName efficiently builds session names using pooled string builders
func BuildSessionName(baseName string, index int) string {
	sb := StringBuilder()
	defer ReturnStringBuilder(sb)

	sb.WriteString(baseName)
	sb.WriteRune('_')
	// Efficient int to string conversion
	if index < 10 {
		sb.WriteRune('0' + rune(index))
	} else {
		sb.WriteString(intToString(index))
	}

	return sb.String()
}

// BuildCacheKey efficiently builds cache keys using pooled string builders
func BuildCacheKey(parts ...string) string {
	sb := StringBuilder()
	defer ReturnStringBuilder(sb)

	for i, part := range parts {
		if i > 0 {
			sb.WriteRune(':')
		}
		sb.WriteString(part)
	}

	return sb.String()
}

// FormatString efficiently formats a string using a pooled string builder
func FormatString(format func(*strings.Builder)) string {
	sb := StringBuilder()
	defer ReturnStringBuilder(sb)
	format(sb)
	return sb.String()
}

// intToString converts int to string without allocation (for small numbers)
func intToString(n int) string {
	if n < 0 {
		return "-" + intToString(-n)
	}
	if n < 10 {
		return string(rune('0' + n))
	}
	if n < 100 {
		return string(rune('0'+n/10)) + string(rune('0'+n%10))
	}
	// Fall back to standard conversion for larger numbers
	buf := make([]byte, 0, 20)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	// Reverse the buffer
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
