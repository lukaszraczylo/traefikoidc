package traefikoidc

import (
	"container/list"
	"time"
)

// Cache compatibility layer - maps old cache types to UniversalCache

// NewCache creates a general purpose cache
func NewCache() CacheInterface {
	config := UniversalCacheConfig{
		Type:    CacheTypeGeneral,
		MaxSize: 1000,
		Logger:  GetSingletonNoOpLogger(),
	}
	return &CacheInterfaceWrapper{
		cache: NewUniversalCache(config),
	}
}

// NewBoundedCache creates a bounded cache with specified max size
func NewBoundedCache(maxSize int) CacheInterface {
	config := UniversalCacheConfig{
		Type:    CacheTypeGeneral,
		MaxSize: maxSize,
		Logger:  GetSingletonNoOpLogger(),
	}
	return &CacheInterfaceWrapper{
		cache: NewUniversalCache(config),
	}
}

// BoundedCache is an alias for compatibility
type BoundedCache = CacheInterfaceWrapper

// BoundedCacheAdapter is an alias for compatibility
type BoundedCacheAdapter = CacheInterfaceWrapper

// UnifiedCache wraps UniversalCache for backward compatibility
type UnifiedCache struct {
	*UniversalCache
	strategy CacheStrategy // For backward compatibility with tests
}

// SetMaxSize sets the maximum cache size
func (c *UnifiedCache) SetMaxSize(size int) {
	c.UniversalCache.SetMaxSize(size)
}

// UnifiedCacheConfig is an alias for backward compatibility
type UnifiedCacheConfig = UniversalCacheConfig

// DefaultUnifiedCacheConfig returns default config for backward compatibility
func DefaultUnifiedCacheConfig() UniversalCacheConfig {
	return UniversalCacheConfig{
		Type:            CacheTypeGeneral,
		MaxSize:         500,
		MaxMemoryBytes:  64 * 1024 * 1024,
		CleanupInterval: 2 * time.Minute,
		Logger:          GetSingletonNoOpLogger(),
	}
}

// NewUnifiedCache creates a universal cache for backward compatibility
func NewUnifiedCache(config UniversalCacheConfig) *UnifiedCache {
	// Avoid circular reference by calling the real constructor
	cache := createUniversalCache(config)
	return &UnifiedCache{
		UniversalCache: cache,
		strategy:       config.Strategy,
	}
}

// CacheAdapter wraps UniversalCache for backward compatibility
type CacheAdapter = CacheInterfaceWrapper

// NewCacheAdapter creates a cache adapter
func NewCacheAdapter(cache interface{}) *CacheInterfaceWrapper {
	switch c := cache.(type) {
	case *UniversalCache:
		return &CacheInterfaceWrapper{cache: c}
	case *UnifiedCache:
		return &CacheInterfaceWrapper{cache: c.UniversalCache}
	default:
		// Try to convert to UniversalCache
		if uc, ok := cache.(*UniversalCache); ok {
			return &CacheInterfaceWrapper{cache: uc}
		}
		return nil
	}
}

// OptimizedCache is an alias for backward compatibility
type OptimizedCache = CacheInterfaceWrapper

// NewOptimizedCache creates an optimized cache
func NewOptimizedCache() *CacheInterfaceWrapper {
	config := UniversalCacheConfig{
		Type:           CacheTypeGeneral,
		MaxSize:        500,
		MaxMemoryBytes: 64 * 1024 * 1024,
		EnableMetrics:  true,
		Logger:         GetSingletonNoOpLogger(),
	}
	return &CacheInterfaceWrapper{
		cache: NewUniversalCache(config),
	}
}

// LRUStrategy for backward compatibility
type LRUStrategy struct {
	order    *list.List
	elements map[string]*list.Element
	maxSize  int
}

func NewLRUStrategy(maxSize int) CacheStrategy {
	return &LRUStrategy{
		order:    list.New(),
		elements: make(map[string]*list.Element),
		maxSize:  maxSize,
	}
}

func (s *LRUStrategy) Name() string {
	return "LRU"
}

func (s *LRUStrategy) ShouldEvict(item interface{}, now time.Time) bool {
	return false
}

func (s *LRUStrategy) OnAccess(key string, item interface{}) {}

func (s *LRUStrategy) OnRemove(key string) {}

func (s *LRUStrategy) EstimateSize(item interface{}) int64 {
	return 64
}

func (s *LRUStrategy) GetEvictionCandidate() (key string, found bool) {
	return "", false
}

// CacheStrategy interface for backward compatibility
type CacheStrategy interface {
	Name() string
	ShouldEvict(item interface{}, now time.Time) bool
	OnAccess(key string, item interface{})
	OnRemove(key string)
	EstimateSize(item interface{}) int64
	GetEvictionCandidate() (key string, found bool)
}

// CacheEntry for backward compatibility
type CacheEntry struct {
	ExpiresAt time.Time
	Value     interface{}
	Key       string
}

// Cache is an alias for backward compatibility
type Cache = CacheInterfaceWrapper

// OptimizedCacheConfig for backward compatibility
type OptimizedCacheConfig = UniversalCacheConfig

// NewOptimizedCacheWithConfig creates cache with config
func NewOptimizedCacheWithConfig(config OptimizedCacheConfig) *CacheInterfaceWrapper {
	return &CacheInterfaceWrapper{
		cache: NewUniversalCache(config),
	}
}

// ListNode for backward compatibility
type ListNode struct {
	Value interface{}
	Next  *ListNode
	Prev  *ListNode
	Key   string
}

// NewFixedMetadataCache creates a metadata cache with fixed configuration
func NewFixedMetadataCache(args ...interface{}) *MetadataCache {
	// Accept variable arguments for backward compatibility
	// Expected args: maxSize, maxMemoryMB, logger
	logger := GetSingletonNoOpLogger()
	maxSize := 100          // default
	maxMemoryMB := int64(0) // default no limit

	if len(args) > 0 {
		if size, ok := args[0].(int); ok {
			maxSize = size
		}
	}
	if len(args) > 1 {
		if memMB, ok := args[1].(int); ok {
			maxMemoryMB = int64(memMB) * 1024 * 1024 // Convert MB to bytes
		}
	}
	if len(args) > 2 {
		if l, ok := args[2].(*Logger); ok {
			logger = l
		}
	}

	// Create a custom cache with the specified max size
	config := UniversalCacheConfig{
		Type:           CacheTypeMetadata,
		MaxSize:        maxSize,
		MaxMemoryBytes: maxMemoryMB,
		DefaultTTL:     1 * time.Hour,
		MetadataConfig: &MetadataCacheConfig{
			GracePeriod:                    5 * time.Minute,
			ExtendedGracePeriod:            15 * time.Minute,
			MaxGracePeriod:                 30 * time.Minute,
			SecurityCriticalMaxGracePeriod: 15 * time.Minute,
		},
		Logger: logger,
	}

	cache := NewUniversalCache(config)
	return &MetadataCache{
		cache:  cache,
		logger: logger,
		wg:     nil,
	}
}

// DoublyLinkedList for backward compatibility
type DoublyLinkedList struct {
	*list.List
}

// NewDoublyLinkedList creates a new doubly linked list
func NewDoublyLinkedList() *DoublyLinkedList {
	return &DoublyLinkedList{
		List: list.New(),
	}
}

// PopFront removes and returns the front element
func (l *DoublyLinkedList) PopFront() interface{} {
	if l.Len() == 0 {
		return nil
	}
	elem := l.Front()
	if elem != nil {
		return l.Remove(elem)
	}
	return nil
}
