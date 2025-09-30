// Package pool provides a unified, centralized memory pool management system
// for the entire application. It consolidates all duplicate pool implementations
// into a single, efficient, and thread-safe package.
package pool

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"sync/atomic"
)

// Manager is the centralized pool manager that consolidates all memory pools
// used throughout the application. It provides a single entry point for
// all pooling operations, reducing duplicate code and improving maintainability.
type Manager struct {
	// Buffer pools
	smallBufferPool  *sync.Pool // 1KB buffers
	mediumBufferPool *sync.Pool // 4KB buffers
	largeBufferPool  *sync.Pool // 8KB buffers
	xlBufferPool     *sync.Pool // 16KB buffers

	// Compression pools
	gzipWriterPool *sync.Pool
	gzipReaderPool *sync.Pool

	// String builder pool
	stringBuilderPool *sync.Pool

	// JWT parsing buffers
	jwtBufferPool *sync.Pool

	// HTTP response buffers
	httpResponsePool *sync.Pool

	// Byte slice pools for various sizes
	byteSlicePools map[int]*sync.Pool
	poolMu         sync.RWMutex

	// Statistics
	stats PoolStats
}

// PoolStats tracks pool usage statistics
type PoolStats struct {
	BufferGets       uint64
	BufferPuts       uint64
	GzipGets         uint64
	GzipPuts         uint64
	StringGets       uint64
	StringPuts       uint64
	JWTGets          uint64
	JWTPuts          uint64
	HTTPGets         uint64
	HTTPPuts         uint64
	JSONEncoderGets  uint64
	JSONEncoderPuts  uint64
	JSONDecoderGets  uint64
	JSONDecoderPuts  uint64
	OversizedRejects uint64
}

// JWTBuffer provides pre-allocated buffers for JWT parsing
type JWTBuffer struct {
	Header    []byte
	Payload   []byte
	Signature []byte
}

var (
	// globalManager is the singleton pool manager instance
	globalManager *Manager
	// managerOnce ensures single initialization
	managerOnce sync.Once
)

// Get returns the global pool manager instance
func Get() *Manager {
	managerOnce.Do(func() {
		globalManager = newManager()
	})
	return globalManager
}

// newManager creates a new pool manager with all pools initialized
func newManager() *Manager {
	m := &Manager{
		byteSlicePools: make(map[int]*sync.Pool),
	}

	// Initialize buffer pools with different sizes
	m.smallBufferPool = &sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, 1024))
		},
	}

	m.mediumBufferPool = &sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, 4096))
		},
	}

	m.largeBufferPool = &sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, 8192))
		},
	}

	m.xlBufferPool = &sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, 16384))
		},
	}

	// Initialize compression pools
	m.gzipWriterPool = &sync.Pool{
		New: func() interface{} {
			w, _ := gzip.NewWriterLevel(nil, gzip.BestSpeed)
			return w
		},
	}

	m.gzipReaderPool = &sync.Pool{
		New: func() interface{} {
			return (*gzip.Reader)(nil)
		},
	}

	// Initialize string builder pool
	m.stringBuilderPool = &sync.Pool{
		New: func() interface{} {
			sb := &strings.Builder{}
			sb.Grow(1024)
			return sb
		},
	}

	// Initialize JWT buffer pool
	m.jwtBufferPool = &sync.Pool{
		New: func() interface{} {
			return &JWTBuffer{
				Header:    make([]byte, 0, 512),
				Payload:   make([]byte, 0, 2048),
				Signature: make([]byte, 0, 512),
			}
		},
	}

	// Initialize HTTP response buffer pool
	m.httpResponsePool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 8192)
			return &buf
		},
	}

	// Initialize common byte slice pools
	for _, size := range []int{256, 512, 1024, 2048, 4096, 8192, 16384} {
		size := size // capture for closure
		m.byteSlicePools[size] = &sync.Pool{
			New: func() interface{} {
				b := make([]byte, size)
				return &b
			},
		}
	}

	return m
}

// GetBuffer returns a buffer from the appropriate pool based on size hint
func (m *Manager) GetBuffer(sizeHint int) *bytes.Buffer {
	atomic.AddUint64(&m.stats.BufferGets, 1)

	switch {
	case sizeHint <= 1024:
		return m.smallBufferPool.Get().(*bytes.Buffer)
	case sizeHint <= 4096:
		return m.mediumBufferPool.Get().(*bytes.Buffer)
	case sizeHint <= 8192:
		return m.largeBufferPool.Get().(*bytes.Buffer)
	case sizeHint <= 16384:
		return m.xlBufferPool.Get().(*bytes.Buffer)
	default:
		// For very large buffers, create new ones
		return bytes.NewBuffer(make([]byte, 0, sizeHint))
	}
}

// PutBuffer returns a buffer to the appropriate pool
func (m *Manager) PutBuffer(buf *bytes.Buffer) {
	if buf == nil {
		return
	}

	atomic.AddUint64(&m.stats.BufferPuts, 1)

	// Reset buffer before returning to pool
	capacity := buf.Cap()
	buf.Reset()

	// Reject oversized buffers to prevent memory bloat
	if capacity > 32768 {
		atomic.AddUint64(&m.stats.OversizedRejects, 1)
		return
	}

	// Return to appropriate pool based on capacity
	switch {
	case capacity <= 1024:
		m.smallBufferPool.Put(buf)
	case capacity <= 4096:
		m.mediumBufferPool.Put(buf)
	case capacity <= 8192:
		m.largeBufferPool.Put(buf)
	case capacity <= 16384:
		m.xlBufferPool.Put(buf)
	}
}

// GetGzipWriter returns a gzip writer from the pool
func (m *Manager) GetGzipWriter() *gzip.Writer {
	atomic.AddUint64(&m.stats.GzipGets, 1)
	return m.gzipWriterPool.Get().(*gzip.Writer)
}

// PutGzipWriter returns a gzip writer to the pool
func (m *Manager) PutGzipWriter(w *gzip.Writer) {
	if w == nil {
		return
	}
	atomic.AddUint64(&m.stats.GzipPuts, 1)
	w.Reset(nil)
	m.gzipWriterPool.Put(w)
}

// GetGzipReader returns a gzip reader from the pool
func (m *Manager) GetGzipReader() *gzip.Reader {
	atomic.AddUint64(&m.stats.GzipGets, 1)
	r := m.gzipReaderPool.Get()
	if r == nil {
		return nil
	}
	return r.(*gzip.Reader)
}

// PutGzipReader returns a gzip reader to the pool
func (m *Manager) PutGzipReader(r *gzip.Reader) {
	if r == nil {
		return
	}
	atomic.AddUint64(&m.stats.GzipPuts, 1)
	r.Reset(nil)
	m.gzipReaderPool.Put(r)
}

// GetStringBuilder returns a string builder from the pool
func (m *Manager) GetStringBuilder() *strings.Builder {
	atomic.AddUint64(&m.stats.StringGets, 1)
	sb := m.stringBuilderPool.Get().(*strings.Builder)
	sb.Reset()
	return sb
}

// PutStringBuilder returns a string builder to the pool
func (m *Manager) PutStringBuilder(sb *strings.Builder) {
	if sb == nil {
		return
	}

	atomic.AddUint64(&m.stats.StringPuts, 1)

	// Reject oversized builders
	if sb.Cap() > 16384 {
		atomic.AddUint64(&m.stats.OversizedRejects, 1)
		return
	}

	sb.Reset()
	m.stringBuilderPool.Put(sb)
}

// GetJWTBuffer returns JWT parsing buffers from the pool
func (m *Manager) GetJWTBuffer() *JWTBuffer {
	atomic.AddUint64(&m.stats.JWTGets, 1)
	return m.jwtBufferPool.Get().(*JWTBuffer)
}

// PutJWTBuffer returns JWT parsing buffers to the pool
func (m *Manager) PutJWTBuffer(buf *JWTBuffer) {
	if buf == nil {
		return
	}

	atomic.AddUint64(&m.stats.JWTPuts, 1)

	// Check for oversized buffers
	if cap(buf.Header) > 2048 || cap(buf.Payload) > 8192 || cap(buf.Signature) > 2048 {
		atomic.AddUint64(&m.stats.OversizedRejects, 1)
		return
	}

	// Reset slices to zero length
	buf.Header = buf.Header[:0]
	buf.Payload = buf.Payload[:0]
	buf.Signature = buf.Signature[:0]
	m.jwtBufferPool.Put(buf)
}

// GetHTTPResponseBuffer returns an HTTP response buffer from the pool
func (m *Manager) GetHTTPResponseBuffer() []byte {
	atomic.AddUint64(&m.stats.HTTPGets, 1)
	return *m.httpResponsePool.Get().(*[]byte)
}

// PutHTTPResponseBuffer returns an HTTP response buffer to the pool
func (m *Manager) PutHTTPResponseBuffer(buf []byte) {
	if buf == nil {
		return
	}

	atomic.AddUint64(&m.stats.HTTPPuts, 1)

	// Reject oversized buffers
	if cap(buf) > 32768 {
		atomic.AddUint64(&m.stats.OversizedRejects, 1)
		return
	}

	buf = buf[:0]
	m.httpResponsePool.Put(&buf)
}

// GetByteSlice returns a byte slice of the specified size from the pool
func (m *Manager) GetByteSlice(size int) []byte {
	m.poolMu.RLock()
	pool, exists := m.byteSlicePools[size]
	m.poolMu.RUnlock()

	if !exists {
		// Round up to nearest power of 2
		poolSize := 1
		for poolSize < size {
			poolSize *= 2
		}

		m.poolMu.Lock()
		// Double-check after acquiring write lock
		pool, exists = m.byteSlicePools[poolSize]
		if !exists {
			pool = &sync.Pool{
				New: func() interface{} {
					b := make([]byte, poolSize)
					return &b
				},
			}
			m.byteSlicePools[poolSize] = pool
		}
		m.poolMu.Unlock()
	}

	b := pool.Get().(*[]byte)
	return (*b)[:size]
}

// PutByteSlice returns a byte slice to the pool
func (m *Manager) PutByteSlice(b []byte) {
	if b == nil || cap(b) > 65536 { // Don't pool very large slices
		return
	}

	size := cap(b)
	m.poolMu.RLock()
	pool, exists := m.byteSlicePools[size]
	m.poolMu.RUnlock()

	if exists {
		b = b[:0]
		pool.Put(&b)
	}
}

// GetJSONEncoder returns a JSON encoder from the pool configured for the given writer
func (m *Manager) GetJSONEncoder(w io.Writer) *json.Encoder {
	atomic.AddUint64(&m.stats.JSONEncoderGets, 1)
	// Since json.Encoder doesn't support resetting, we create new ones each time
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false) // Disable HTML escaping for performance
	return encoder
}

// PutJSONEncoder returns a JSON encoder to the pool
func (m *Manager) PutJSONEncoder(encoder *json.Encoder) {
	if encoder == nil {
		return
	}
	atomic.AddUint64(&m.stats.JSONEncoderPuts, 1)
	// JSON encoders can't be reset, so we don't pool them
}

// GetJSONDecoder returns a JSON decoder from the pool configured for the given reader
func (m *Manager) GetJSONDecoder(r io.Reader) *json.Decoder {
	atomic.AddUint64(&m.stats.JSONDecoderGets, 1)
	// Since json.Decoder doesn't support resetting, we create new ones each time
	return json.NewDecoder(r)
}

// PutJSONDecoder returns a JSON decoder to the pool
func (m *Manager) PutJSONDecoder(decoder *json.Decoder) {
	if decoder == nil {
		return
	}
	atomic.AddUint64(&m.stats.JSONDecoderPuts, 1)
	// JSON decoders can't be reset, so we don't pool them
}

// GetStats returns current pool statistics
func (m *Manager) GetStats() PoolStats {
	return PoolStats{
		BufferGets:       atomic.LoadUint64(&m.stats.BufferGets),
		BufferPuts:       atomic.LoadUint64(&m.stats.BufferPuts),
		GzipGets:         atomic.LoadUint64(&m.stats.GzipGets),
		GzipPuts:         atomic.LoadUint64(&m.stats.GzipPuts),
		StringGets:       atomic.LoadUint64(&m.stats.StringGets),
		StringPuts:       atomic.LoadUint64(&m.stats.StringPuts),
		JWTGets:          atomic.LoadUint64(&m.stats.JWTGets),
		JWTPuts:          atomic.LoadUint64(&m.stats.JWTPuts),
		HTTPGets:         atomic.LoadUint64(&m.stats.HTTPGets),
		HTTPPuts:         atomic.LoadUint64(&m.stats.HTTPPuts),
		JSONEncoderGets:  atomic.LoadUint64(&m.stats.JSONEncoderGets),
		JSONEncoderPuts:  atomic.LoadUint64(&m.stats.JSONEncoderPuts),
		JSONDecoderGets:  atomic.LoadUint64(&m.stats.JSONDecoderGets),
		JSONDecoderPuts:  atomic.LoadUint64(&m.stats.JSONDecoderPuts),
		OversizedRejects: atomic.LoadUint64(&m.stats.OversizedRejects),
	}
}

// ResetStats resets all statistics counters
func (m *Manager) ResetStats() {
	atomic.StoreUint64(&m.stats.BufferGets, 0)
	atomic.StoreUint64(&m.stats.BufferPuts, 0)
	atomic.StoreUint64(&m.stats.GzipGets, 0)
	atomic.StoreUint64(&m.stats.GzipPuts, 0)
	atomic.StoreUint64(&m.stats.StringGets, 0)
	atomic.StoreUint64(&m.stats.StringPuts, 0)
	atomic.StoreUint64(&m.stats.JWTGets, 0)
	atomic.StoreUint64(&m.stats.JWTPuts, 0)
	atomic.StoreUint64(&m.stats.HTTPGets, 0)
	atomic.StoreUint64(&m.stats.HTTPPuts, 0)
	atomic.StoreUint64(&m.stats.JSONEncoderGets, 0)
	atomic.StoreUint64(&m.stats.JSONEncoderPuts, 0)
	atomic.StoreUint64(&m.stats.JSONDecoderGets, 0)
	atomic.StoreUint64(&m.stats.JSONDecoderPuts, 0)
	atomic.StoreUint64(&m.stats.OversizedRejects, 0)
}

// Global convenience functions

// Buffer returns a buffer from the global pool
func Buffer(sizeHint int) *bytes.Buffer {
	return Get().GetBuffer(sizeHint)
}

// ReturnBuffer returns a buffer to the global pool
func ReturnBuffer(buf *bytes.Buffer) {
	Get().PutBuffer(buf)
}

// GzipWriter returns a gzip writer from the global pool
func GzipWriter() *gzip.Writer {
	return Get().GetGzipWriter()
}

// ReturnGzipWriter returns a gzip writer to the global pool
func ReturnGzipWriter(w *gzip.Writer) {
	Get().PutGzipWriter(w)
}

// StringBuilder returns a string builder from the global pool
func StringBuilder() *strings.Builder {
	return Get().GetStringBuilder()
}

// ReturnStringBuilder returns a string builder to the global pool
func ReturnStringBuilder(sb *strings.Builder) {
	Get().PutStringBuilder(sb)
}

// JWTBuffers returns JWT parsing buffers from the global pool
func JWTBuffers() *JWTBuffer {
	return Get().GetJWTBuffer()
}

// ReturnJWTBuffers returns JWT parsing buffers to the global pool
func ReturnJWTBuffers(buf *JWTBuffer) {
	Get().PutJWTBuffer(buf)
}

// HTTPBuffer returns an HTTP response buffer from the global pool
func HTTPBuffer() []byte {
	return Get().GetHTTPResponseBuffer()
}

// ReturnHTTPBuffer returns an HTTP response buffer to the global pool
func ReturnHTTPBuffer(buf []byte) {
	Get().PutHTTPResponseBuffer(buf)
}

// ByteSlice returns a byte slice from the global pool
func ByteSlice(size int) []byte {
	return Get().GetByteSlice(size)
}

// ReturnByteSlice returns a byte slice to the global pool
func ReturnByteSlice(b []byte) {
	Get().PutByteSlice(b)
}

// JSONEncoder returns a JSON encoder from the global pool
func JSONEncoder(w io.Writer) *json.Encoder {
	return Get().GetJSONEncoder(w)
}

// ReturnJSONEncoder returns a JSON encoder to the global pool
func ReturnJSONEncoder(encoder *json.Encoder) {
	Get().PutJSONEncoder(encoder)
}

// JSONDecoder returns a JSON decoder from the global pool
func JSONDecoder(r io.Reader) *json.Decoder {
	return Get().GetJSONDecoder(r)
}

// ReturnJSONDecoder returns a JSON decoder to the global pool
func ReturnJSONDecoder(decoder *json.Decoder) {
	Get().PutJSONDecoder(decoder)
}
