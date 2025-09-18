package traefikoidc

import (
	"bytes"
	"strings"
	"sync"
)

// MemoryPoolManager provides centralized management of object pools for memory efficiency.
// It maintains pools for frequently allocated objects like buffers for compression, JWT parsing,
// HTTP responses, and string building operations to reduce garbage collection pressure.
type MemoryPoolManager struct {
	// compressionBufferPool pools buffers for compression/decompression operations
	compressionBufferPool *sync.Pool
	// jwtParsingPool pools specialized buffers for JWT token parsing
	jwtParsingPool *sync.Pool
	// httpResponsePool pools buffers for HTTP response handling
	httpResponsePool *sync.Pool
	// stringBuilderPool pools string.Builder instances for string operations
	stringBuilderPool *sync.Pool
}

// JWTParsingBuffer provides pre-allocated buffers for JWT token parsing.
// Using pooled buffers for the three JWT components (header, payload, signature)
// avoids repeated allocations during token validation, which can significantly
// improve performance under high load.
type JWTParsingBuffer struct {
	// HeaderBuf stores the decoded JWT header
	HeaderBuf []byte
	// PayloadBuf stores the decoded JWT payload/claims
	PayloadBuf []byte
	// SignatureBuf stores the decoded JWT signature
	SignatureBuf []byte
}

// NewMemoryPoolManager creates a new memory pool manager with optimized pool configurations.
// Each pool is initialized with appropriate buffer sizes to balance memory usage with performance benefits.
func NewMemoryPoolManager() *MemoryPoolManager {
	return &MemoryPoolManager{
		compressionBufferPool: &sync.Pool{
			New: func() interface{} {
				return bytes.NewBuffer(make([]byte, 0, 4096))
			},
		},

		jwtParsingPool: &sync.Pool{
			New: func() interface{} {
				return &JWTParsingBuffer{
					HeaderBuf:    make([]byte, 0, 512),
					PayloadBuf:   make([]byte, 0, 2048),
					SignatureBuf: make([]byte, 0, 512),
				}
			},
		},

		httpResponsePool: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 0, 8192)
				return &buf
			},
		},

		stringBuilderPool: &sync.Pool{
			New: func() interface{} {
				var sb strings.Builder
				sb.Grow(1024)
				return &sb
			},
		},
	}
}

// GetCompressionBuffer retrieves a buffer from the compression pool.
// The buffer should be returned to the pool using PutCompressionBuffer when done.
func (m *MemoryPoolManager) GetCompressionBuffer() *bytes.Buffer {
	return m.compressionBufferPool.Get().(*bytes.Buffer)
}

// PutCompressionBuffer returns a compression buffer to the pool.
// The buffer is reset before being returned to prevent data leaks.
// Oversized buffers are discarded to prevent memory bloat.
func (m *MemoryPoolManager) PutCompressionBuffer(buf *bytes.Buffer) {
	if buf == nil {
		return
	}

	if buf.Cap() <= 16384 {
		buf.Reset()
		m.compressionBufferPool.Put(buf)
	}
}

// GetJWTParsingBuffer retrieves specialized buffers for JWT parsing.
// Returns a structure with pre-allocated buffers for header, payload, and signature.
func (m *MemoryPoolManager) GetJWTParsingBuffer() *JWTParsingBuffer {
	return m.jwtParsingPool.Get().(*JWTParsingBuffer)
}

// PutJWTParsingBuffer returns JWT parsing buffers to the pool.
// All buffer slices are reset to zero length and oversized buffers are discarded.
func (m *MemoryPoolManager) PutJWTParsingBuffer(buf *JWTParsingBuffer) {
	if buf == nil {
		return
	}

	if cap(buf.HeaderBuf) <= 2048 && cap(buf.PayloadBuf) <= 8192 && cap(buf.SignatureBuf) <= 2048 {
		buf.HeaderBuf = buf.HeaderBuf[:0]
		buf.PayloadBuf = buf.PayloadBuf[:0]
		buf.SignatureBuf = buf.SignatureBuf[:0]
		m.jwtParsingPool.Put(buf)
	}
}

// GetHTTPResponseBuffer retrieves a buffer for HTTP response handling.
// Returns a pre-allocated byte slice suitable for HTTP operations.
func (m *MemoryPoolManager) GetHTTPResponseBuffer() []byte {
	return *m.httpResponsePool.Get().(*[]byte)
}

// PutHTTPResponseBuffer returns an HTTP response buffer to the pool.
// The buffer slice is reset to zero length and oversized buffers are discarded.
func (m *MemoryPoolManager) PutHTTPResponseBuffer(buf []byte) {
	if buf == nil {
		return
	}

	if cap(buf) <= 32768 {
		buf = buf[:0]
		m.httpResponsePool.Put(&buf)
	}
}

// GetStringBuilder retrieves a pre-allocated string builder from the pool.
// The string builder is ready for use with an initial capacity allocation.
func (m *MemoryPoolManager) GetStringBuilder() *strings.Builder {
	return m.stringBuilderPool.Get().(*strings.Builder)
}

// PutStringBuilder returns a string builder to the pool.
// The builder is reset and oversized builders are discarded to prevent memory bloat.
func (m *MemoryPoolManager) PutStringBuilder(sb *strings.Builder) {
	if sb == nil {
		return
	}

	if sb.Cap() <= 16384 {
		sb.Reset()
		m.stringBuilderPool.Put(sb)
	}
}

// TokenCompressionPool manages specialized memory pools for token compression operations.
// Provides separate pools optimized for compression, decompression, and string building
// to handle the specific memory patterns of token processing workflows.
type TokenCompressionPool struct {
	// compressionBuffers pools buffers specifically sized for token compression
	compressionBuffers sync.Pool
	// decompressionBuffers pools buffers for token decompression with larger capacity
	decompressionBuffers sync.Pool
	// stringBuilders pools string builders optimized for token operations
	stringBuilders sync.Pool
}

// NewTokenCompressionPool creates a specialized memory pool for token operations.
// Initializes pools with buffer sizes optimized for token compression workflows.
func NewTokenCompressionPool() *TokenCompressionPool {
	return &TokenCompressionPool{
		compressionBuffers: sync.Pool{
			New: func() interface{} {
				return bytes.NewBuffer(make([]byte, 0, 4096))
			},
		},
		decompressionBuffers: sync.Pool{
			New: func() interface{} {
				return bytes.NewBuffer(make([]byte, 0, 8192))
			},
		},
		stringBuilders: sync.Pool{
			New: func() interface{} {
				var sb strings.Builder
				sb.Grow(2048)
				return &sb
			},
		},
	}
}

// GetCompressionBuffer retrieves a buffer optimized for token compression.
// Returns a buffer with appropriate capacity for typical token sizes.
func (p *TokenCompressionPool) GetCompressionBuffer() *bytes.Buffer {
	return p.compressionBuffers.Get().(*bytes.Buffer)
}

// PutCompressionBuffer returns a compression buffer to the pool.
// Resets the buffer and discards oversized buffers to prevent memory bloat.
func (p *TokenCompressionPool) PutCompressionBuffer(buf *bytes.Buffer) {
	if buf != nil && buf.Cap() <= 16384 {
		buf.Reset()
		p.compressionBuffers.Put(buf)
	}
}

// GetDecompressionBuffer retrieves a buffer optimized for token decompression.
// Returns a larger buffer suitable for expanded token data.
func (p *TokenCompressionPool) GetDecompressionBuffer() *bytes.Buffer {
	return p.decompressionBuffers.Get().(*bytes.Buffer)
}

// PutDecompressionBuffer returns a decompression buffer to the pool.
// Resets the buffer and discards oversized buffers to prevent memory bloat.
func (p *TokenCompressionPool) PutDecompressionBuffer(buf *bytes.Buffer) {
	if buf != nil && buf.Cap() <= 32768 {
		buf.Reset()
		p.decompressionBuffers.Put(buf)
	}
}

// GetStringBuilder retrieves a string builder optimized for token operations.
// Returns a pre-allocated builder with capacity suitable for token processing.
func (p *TokenCompressionPool) GetStringBuilder() *strings.Builder {
	return p.stringBuilders.Get().(*strings.Builder)
}

// PutStringBuilder returns a string builder to the pool.
// Resets the builder and discards oversized builders to prevent memory bloat.
func (p *TokenCompressionPool) PutStringBuilder(sb *strings.Builder) {
	if sb != nil && sb.Cap() <= 16384 {
		sb.Reset()
		p.stringBuilders.Put(sb)
	}
}

// Global memory pool manager instance and synchronization primitives.
// Provides singleton access to memory pools across the entire application.
var (
	// globalMemoryPools is the singleton memory pool manager instance
	globalMemoryPools *MemoryPoolManager
	// memoryPoolOnce ensures single initialization of the global pools
	memoryPoolOnce sync.Once
	// memoryPoolMutex protects global pool operations
	memoryPoolMutex sync.RWMutex
)

// GetGlobalMemoryPools returns the singleton memory pool manager instance.
// Uses sync.Once to ensure thread-safe initialization of the global pools.
func GetGlobalMemoryPools() *MemoryPoolManager {
	memoryPoolOnce.Do(func() {
		globalMemoryPools = NewMemoryPoolManager()
	})
	return globalMemoryPools
}

// CleanupGlobalMemoryPools cleans up the global memory pool manager.
// Resets the singleton instance and sync.Once for potential re-initialization.
// It's safe to call multiple times.
func CleanupGlobalMemoryPools() {
	memoryPoolMutex.Lock()
	defer memoryPoolMutex.Unlock()

	if globalMemoryPools != nil {
		globalMemoryPools = nil
		memoryPoolOnce = sync.Once{}
	}
}
