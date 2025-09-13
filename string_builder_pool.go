package traefikoidc

import (
	"strings"
	"sync"
)

// StringBuilderPool manages a pool of string builders for efficient string operations
type StringBuilderPool struct {
	pool sync.Pool
}

var (
	globalStringBuilderPool     *StringBuilderPool
	globalStringBuilderPoolOnce sync.Once
)

// GetGlobalStringBuilderPool returns the global string builder pool
func GetGlobalStringBuilderPool() *StringBuilderPool {
	globalStringBuilderPoolOnce.Do(func() {
		globalStringBuilderPool = &StringBuilderPool{
			pool: sync.Pool{
				New: func() interface{} {
					return &strings.Builder{}
				},
			},
		}
	})
	return globalStringBuilderPool
}

// Get retrieves a string builder from the pool
func (p *StringBuilderPool) Get() *strings.Builder {
	sb := p.pool.Get().(*strings.Builder)
	sb.Reset() // Ensure it's clean
	return sb
}

// Put returns a string builder to the pool
func (p *StringBuilderPool) Put(sb *strings.Builder) {
	if sb == nil {
		return
	}
	// Only return to pool if not too large (avoid keeping huge buffers)
	if sb.Cap() <= 4096 {
		sb.Reset()
		p.pool.Put(sb)
	}
}

// FormatString efficiently formats a string using the pool
func (p *StringBuilderPool) FormatString(format func(*strings.Builder)) string {
	sb := p.Get()
	defer p.Put(sb)
	format(sb)
	return sb.String()
}

// BuildSessionName efficiently builds session names
func BuildSessionName(baseName string, index int) string {
	pool := GetGlobalStringBuilderPool()
	return pool.FormatString(func(sb *strings.Builder) {
		sb.WriteString(baseName)
		sb.WriteRune('_')
		// Efficient int to string conversion
		if index < 10 {
			sb.WriteRune('0' + rune(index))
		} else {
			sb.WriteString(sbIntToString(index))
		}
	})
}

// BuildCacheKey efficiently builds cache keys
func BuildCacheKey(parts ...string) string {
	pool := GetGlobalStringBuilderPool()
	return pool.FormatString(func(sb *strings.Builder) {
		for i, part := range parts {
			if i > 0 {
				sb.WriteRune(':')
			}
			sb.WriteString(part)
		}
	})
}

// sbIntToString converts int to string without allocation (for small numbers)
func sbIntToString(n int) string {
	if n < 0 {
		return "-" + sbIntToString(-n)
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
