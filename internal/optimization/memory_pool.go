// Package optimization provides memory and performance optimizations
package optimization

import (
	"sync"
)

// StringBuilderPool provides a pool of reusable string builders
type StringBuilderPool struct {
	pool sync.Pool
}

// NewStringBuilderPool creates a new string builder pool
func NewStringBuilderPool() *StringBuilderPool {
	return &StringBuilderPool{
		pool: sync.Pool{
			New: func() any {
				return make([]byte, 0, 256) // Pre-allocate 256 bytes
			},
		},
	}
}

// Get retrieves a string builder from the pool
func (p *StringBuilderPool) Get() []byte {
	buf := p.pool.Get().([]byte)
	// Return the slice with reset length but preserved capacity
	return buf[:0]
}

// Put returns a string builder to the pool
func (p *StringBuilderPool) Put(buf []byte) {
	if buf != nil && cap(buf) < 4096 { // Don't pool overly large buffers or nil buffers
		// Intentional design: slice API is more ergonomic than *[]byte.
		// The 24-byte boxing allocation is negligible compared to 256+ byte buffer allocation we avoid.
		//lint:ignore SA6002 slice interface is preferred over pointer interface for ergonomics
		p.pool.Put(buf[:0]) // Reset length and store the slice directly
	}
}

// ByteSlicePool provides a pool of reusable byte slices
type ByteSlicePool struct {
	pool sync.Pool
	size int
}

// NewByteSlicePool creates a new byte slice pool with specified size
func NewByteSlicePool(size int) *ByteSlicePool {
	return &ByteSlicePool{
		size: size,
		pool: sync.Pool{
			New: func() any {
				return make([]byte, size)
			},
		},
	}
}

// Get retrieves a byte slice from the pool
func (p *ByteSlicePool) Get() []byte {
	buf := p.pool.Get().([]byte)
	// Ensure we're returning the full-sized slice
	return buf[:p.size]
}

// Put returns a byte slice to the pool
func (p *ByteSlicePool) Put(buf []byte) {
	if buf != nil && len(buf) == p.size {
		// Intentional design: slice API is more ergonomic than *[]byte.
		// The 24-byte boxing allocation is negligible compared to the sized buffer allocation we avoid.
		//lint:ignore SA6002 slice interface is preferred over pointer interface for ergonomics
		p.pool.Put(buf)
	}
}

// Global pools for common use cases
var (
	globalStringBuilderPool = NewStringBuilderPool()
	globalByteSlicePool     = NewByteSlicePool(2048)
)

// GetStringBuilder gets a string builder from the global pool
func GetStringBuilder() []byte {
	return globalStringBuilderPool.Get()
}

// PutStringBuilder returns a string builder to the global pool
func PutStringBuilder(buf []byte) {
	globalStringBuilderPool.Put(buf)
}

// GetByteSlice gets a byte slice from the global pool
func GetByteSlice() []byte {
	return globalByteSlicePool.Get()
}

// PutByteSlice returns a byte slice to the global pool
func PutByteSlice(buf []byte) {
	globalByteSlicePool.Put(buf)
}
