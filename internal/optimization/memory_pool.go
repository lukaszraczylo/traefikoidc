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
				buf := make([]byte, 0, 256) // Pre-allocate 256 bytes
				return &buf
			},
		},
	}
}

// Get retrieves a string builder from the pool
func (p *StringBuilderPool) Get() []byte {
	bufPtr := p.pool.Get().(*[]byte)
	return *bufPtr
}

// Put returns a string builder to the pool
func (p *StringBuilderPool) Put(buf []byte) {
	if buf != nil && cap(buf) < 4096 { // Don't pool overly large buffers or nil buffers
		buf = buf[:0] // Reset length but keep capacity
		p.pool.Put(&buf)
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
				buf := make([]byte, size)
				return &buf
			},
		},
	}
}

// Get retrieves a byte slice from the pool
func (p *ByteSlicePool) Get() []byte {
	bufPtr := p.pool.Get().(*[]byte)
	return *bufPtr
}

// Put returns a byte slice to the pool
func (p *ByteSlicePool) Put(buf []byte) {
	if buf != nil && len(buf) == p.size {
		p.pool.Put(&buf)
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
