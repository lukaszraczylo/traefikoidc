package traefikoidc

import (
	"bytes"
	"strings"
	"sync"
)

// MemoryPoolManager manages various memory pools for high-frequency allocations
// to reduce garbage collection pressure and improve performance. It provides
// thread-safe object pools for compression buffers, JWT parsing, HTTP responses,
// and string building operations.
type MemoryPoolManager struct {
	compressionBufferPool *sync.Pool
	jwtParsingPool        *sync.Pool
	httpResponsePool      *sync.Pool
	stringBuilderPool     *sync.Pool
}

// JWTParsingBuffer contains reusable byte buffers for JWT parsing operations.
// By reusing these buffers, we avoid frequent allocations during token validation,
// which can significantly improve performance under high load.
type JWTParsingBuffer struct {
	HeaderBuf    []byte
	PayloadBuf   []byte
	SignatureBuf []byte
}

// NewMemoryPoolManager creates and initializes all memory pools with appropriate
// default sizes based on typical usage patterns. The pools are configured to
// balance memory usage with performance benefits.
func NewMemoryPoolManager() *MemoryPoolManager {
	return &MemoryPoolManager{
		// Pool for compression/decompression buffers (4KB default)
		compressionBufferPool: &sync.Pool{
			New: func() interface{} {
				return bytes.NewBuffer(make([]byte, 0, 4096))
			},
		},

		// Pool for JWT parsing buffers
		jwtParsingPool: &sync.Pool{
			New: func() interface{} {
				return &JWTParsingBuffer{
					HeaderBuf:    make([]byte, 0, 512),  // JWT headers are typically small
					PayloadBuf:   make([]byte, 0, 2048), // Payloads can be larger
					SignatureBuf: make([]byte, 0, 512),  // Signatures are fixed size
				}
			},
		},

		// Pool for HTTP response buffers (8KB default)
		httpResponsePool: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 0, 8192)
				return &buf
			},
		},

		// Pool for string builders
		stringBuilderPool: &sync.Pool{
			New: func() interface{} {
				var sb strings.Builder
				sb.Grow(1024) // Pre-allocate 1KB
				return &sb
			},
		},
	}
}

// GetCompressionBuffer retrieves a reusable buffer from the compression pool.
// The buffer should be returned to the pool using PutCompressionBuffer when done.
func (m *MemoryPoolManager) GetCompressionBuffer() *bytes.Buffer {
	return m.compressionBufferPool.Get().(*bytes.Buffer)
}

// PutCompressionBuffer returns a buffer to the compression pool for reuse.
// Buffers larger than 16KB are not pooled to prevent excessive memory retention.
// The buffer is reset before being returned to the pool.
func (m *MemoryPoolManager) PutCompressionBuffer(buf *bytes.Buffer) {
	if buf == nil {
		return
	}

	// Reset buffer but keep capacity if reasonable size
	if buf.Cap() <= 16384 { // Don't pool buffers larger than 16KB
		buf.Reset()
		m.compressionBufferPool.Put(buf)
	}
}

// GetJWTParsingBuffer retrieves buffers for JWT parsing
func (m *MemoryPoolManager) GetJWTParsingBuffer() *JWTParsingBuffer {
	return m.jwtParsingPool.Get().(*JWTParsingBuffer)
}

// PutJWTParsingBuffer returns JWT parsing buffers to the pool
func (m *MemoryPoolManager) PutJWTParsingBuffer(buf *JWTParsingBuffer) {
	if buf == nil {
		return
	}

	// Reset buffers but keep capacity if reasonable
	if cap(buf.HeaderBuf) <= 2048 && cap(buf.PayloadBuf) <= 8192 && cap(buf.SignatureBuf) <= 2048 {
		buf.HeaderBuf = buf.HeaderBuf[:0]
		buf.PayloadBuf = buf.PayloadBuf[:0]
		buf.SignatureBuf = buf.SignatureBuf[:0]
		m.jwtParsingPool.Put(buf)
	}
}

// GetHTTPResponseBuffer retrieves a buffer for HTTP responses
func (m *MemoryPoolManager) GetHTTPResponseBuffer() []byte {
	return *m.httpResponsePool.Get().(*[]byte)
}

// PutHTTPResponseBuffer returns an HTTP response buffer to the pool
func (m *MemoryPoolManager) PutHTTPResponseBuffer(buf []byte) {
	if buf == nil {
		return
	}

	// Don't pool extremely large buffers
	if cap(buf) <= 32768 { // 32KB limit
		buf = buf[:0] // Reset length but keep capacity
		m.httpResponsePool.Put(&buf)
	}
}

// GetStringBuilder retrieves a string builder from the pool
func (m *MemoryPoolManager) GetStringBuilder() *strings.Builder {
	return m.stringBuilderPool.Get().(*strings.Builder)
}

// PutStringBuilder returns a string builder to the pool
func (m *MemoryPoolManager) PutStringBuilder(sb *strings.Builder) {
	if sb == nil {
		return
	}

	// Don't pool extremely large builders
	if sb.Cap() <= 16384 { // 16KB limit
		sb.Reset()
		m.stringBuilderPool.Put(sb)
	}
}

// TokenCompressionPool manages memory pools for token compression operations
type TokenCompressionPool struct {
	compressionBuffers   sync.Pool
	decompressionBuffers sync.Pool
	stringBuilders       sync.Pool
}

// NewTokenCompressionPool creates a specialized pool for token operations
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
				sb.Grow(2048) // Pre-allocate for token operations
				return &sb
			},
		},
	}
}

// GetCompressionBuffer gets a buffer for compression
func (p *TokenCompressionPool) GetCompressionBuffer() *bytes.Buffer {
	return p.compressionBuffers.Get().(*bytes.Buffer)
}

// PutCompressionBuffer returns a compression buffer
func (p *TokenCompressionPool) PutCompressionBuffer(buf *bytes.Buffer) {
	if buf != nil && buf.Cap() <= 16384 {
		buf.Reset()
		p.compressionBuffers.Put(buf)
	}
}

// GetDecompressionBuffer gets a buffer for decompression
func (p *TokenCompressionPool) GetDecompressionBuffer() *bytes.Buffer {
	return p.decompressionBuffers.Get().(*bytes.Buffer)
}

// PutDecompressionBuffer returns a decompression buffer
func (p *TokenCompressionPool) PutDecompressionBuffer(buf *bytes.Buffer) {
	if buf != nil && buf.Cap() <= 32768 {
		buf.Reset()
		p.decompressionBuffers.Put(buf)
	}
}

// GetStringBuilder gets a string builder for token operations
func (p *TokenCompressionPool) GetStringBuilder() *strings.Builder {
	return p.stringBuilders.Get().(*strings.Builder)
}

// PutStringBuilder returns a string builder
func (p *TokenCompressionPool) PutStringBuilder(sb *strings.Builder) {
	if sb != nil && sb.Cap() <= 16384 {
		sb.Reset()
		p.stringBuilders.Put(sb)
	}
}

// Global memory pool manager instance
var globalMemoryPools *MemoryPoolManager
var memoryPoolOnce sync.Once

// GetGlobalMemoryPools returns the singleton memory pool manager
func GetGlobalMemoryPools() *MemoryPoolManager {
	memoryPoolOnce.Do(func() {
		globalMemoryPools = NewMemoryPoolManager()
	})
	return globalMemoryPools
}
