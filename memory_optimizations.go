package traefikoidc

import (
	"bytes"
	"compress/gzip"
	"sync"
)

// MemoryOptimizations contains all memory optimization utilities
type MemoryOptimizations struct {
	bufferPool      *BufferPool
	gzipWriterPool  *GzipWriterPool
	gzipReaderPool  *GzipReaderPool
	loggerSingleton *Logger
	loggerOnce      sync.Once
}

var (
	globalMemoryOpts     *MemoryOptimizations
	globalMemoryOptsOnce sync.Once
)

// GetMemoryOptimizations returns the global memory optimizations instance
func GetMemoryOptimizations() *MemoryOptimizations {
	globalMemoryOptsOnce.Do(func() {
		globalMemoryOpts = &MemoryOptimizations{
			bufferPool:     NewBufferPool(4096),
			gzipWriterPool: NewGzipWriterPool(),
			gzipReaderPool: NewGzipReaderPool(),
		}
	})
	return globalMemoryOpts
}

// BufferPool manages a pool of byte buffers
type BufferPool struct {
	pool    sync.Pool
	maxSize int
}

// NewBufferPool creates a new buffer pool
func NewBufferPool(maxSize int) *BufferPool {
	return &BufferPool{
		maxSize: maxSize,
		pool: sync.Pool{
			New: func() interface{} {
				return bytes.NewBuffer(make([]byte, 0, 1024))
			},
		},
	}
}

// Get retrieves a buffer from the pool
func (p *BufferPool) Get() *bytes.Buffer {
	buf := p.pool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// Put returns a buffer to the pool
func (p *BufferPool) Put(buf *bytes.Buffer) {
	if buf == nil {
		return
	}
	// Only pool if not too large
	if buf.Cap() <= p.maxSize {
		buf.Reset()
		p.pool.Put(buf)
	}
}

// GzipWriterPool manages a pool of gzip writers
type GzipWriterPool struct {
	pool sync.Pool
}

// NewGzipWriterPool creates a new gzip writer pool
func NewGzipWriterPool() *GzipWriterPool {
	return &GzipWriterPool{
		pool: sync.Pool{
			New: func() interface{} {
				w, _ := gzip.NewWriterLevel(nil, gzip.BestSpeed)
				return w
			},
		},
	}
}

// Get retrieves a gzip writer from the pool
func (p *GzipWriterPool) Get() *gzip.Writer {
	return p.pool.Get().(*gzip.Writer)
}

// Put returns a gzip writer to the pool
func (p *GzipWriterPool) Put(w *gzip.Writer) {
	if w != nil {
		w.Reset(nil)
		p.pool.Put(w)
	}
}

// GzipReaderPool manages a pool of gzip readers
type GzipReaderPool struct {
	pool sync.Pool
}

// NewGzipReaderPool creates a new gzip reader pool
func NewGzipReaderPool() *GzipReaderPool {
	return &GzipReaderPool{
		pool: sync.Pool{
			New: func() interface{} {
				// Return nil, readers will be created as needed
				return (*gzip.Reader)(nil)
			},
		},
	}
}

// Get retrieves a gzip reader from the pool
func (p *GzipReaderPool) Get() *gzip.Reader {
	r := p.pool.Get()
	if r == nil {
		return nil
	}
	return r.(*gzip.Reader)
}

// Put returns a gzip reader to the pool
func (p *GzipReaderPool) Put(r *gzip.Reader) {
	if r != nil {
		r.Reset(nil)
		p.pool.Put(r)
	}
}

// GetSingletonLogger returns a singleton logger instance
func (m *MemoryOptimizations) GetSingletonLogger(level string) *Logger {
	m.loggerOnce.Do(func() {
		m.loggerSingleton = NewLogger(level)
	})
	return m.loggerSingleton
}

// CompressTokenOptimized compresses a token using pooled resources
func CompressTokenOptimized(token string) (string, error) {
	opts := GetMemoryOptimizations()

	buf := opts.bufferPool.Get()
	defer opts.bufferPool.Put(buf)

	gzipWriter := opts.gzipWriterPool.Get()
	defer opts.gzipWriterPool.Put(gzipWriter)

	gzipWriter.Reset(buf)

	if _, err := gzipWriter.Write([]byte(token)); err != nil {
		return token, err
	}

	if err := gzipWriter.Close(); err != nil {
		return token, err
	}

	compressed := buf.Bytes()

	// Only use compression if it's beneficial
	if len(compressed) < len(token) {
		return string(compressed), nil
	}

	return token, nil
}

// DecompressTokenOptimized decompresses a token using pooled resources
func DecompressTokenOptimized(compressed string) (string, error) {
	opts := GetMemoryOptimizations()

	buf := bytes.NewReader([]byte(compressed))

	gzipReader, err := gzip.NewReader(buf)
	if err != nil {
		return compressed, err
	}
	defer gzipReader.Close()

	outputBuf := opts.bufferPool.Get()
	defer opts.bufferPool.Put(outputBuf)

	if _, err := outputBuf.ReadFrom(gzipReader); err != nil {
		return compressed, err
	}

	return outputBuf.String(), nil
}

// SimplifiedSessionData represents a simplified session structure with fewer references
type SimplifiedSessionData struct {
	mainData map[string]interface{}
	tokens   map[string]string
	chunks   map[string][]string
	mu       sync.RWMutex
}

// NewSimplifiedSessionData creates a new simplified session data structure
func NewSimplifiedSessionData() *SimplifiedSessionData {
	return &SimplifiedSessionData{
		mainData: make(map[string]interface{}),
		tokens:   make(map[string]string),
		chunks:   make(map[string][]string),
	}
}

// SetToken sets a token value
func (s *SimplifiedSessionData) SetToken(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[name] = value
}

// GetToken gets a token value
func (s *SimplifiedSessionData) GetToken(name string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, exists := s.tokens[name]
	return val, exists
}

// Clear clears all session data
func (s *SimplifiedSessionData) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mainData = make(map[string]interface{})
	s.tokens = make(map[string]string)
	s.chunks = make(map[string][]string)
}
