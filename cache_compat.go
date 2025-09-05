package traefikoidc

// Cache compatibility layer - maps old cache types to UnifiedCache

// Cache is now an alias for CacheAdapter wrapping UnifiedCache
type Cache = CacheAdapter

// NewCache creates a UnifiedCache with default configuration
// This maintains backward compatibility with existing code
func NewCache() *CacheAdapter {
	config := DefaultUnifiedCacheConfig()
	unifiedCache := NewUnifiedCache(config)
	return NewCacheAdapter(unifiedCache)
}

// OptimizedCache is now an alias for CacheAdapter wrapping UnifiedCache
type OptimizedCache = CacheAdapter

// NewOptimizedCache creates a UnifiedCache with optimized configuration
// This maintains backward compatibility with existing code
func NewOptimizedCache() *CacheAdapter {
	config := DefaultUnifiedCacheConfig()
	config.EnableMemoryLimit = true
	config.Strategy = NewLRUStrategy(config.MaxSize)
	unifiedCache := NewUnifiedCache(config)
	return NewCacheAdapter(unifiedCache)
}

// OptimizedCacheConfig is an alias for UnifiedCacheConfig
type OptimizedCacheConfig = UnifiedCacheConfig

// NewOptimizedCacheWithConfig creates a UnifiedCache with custom configuration
func NewOptimizedCacheWithConfig(config OptimizedCacheConfig) *CacheAdapter {
	unifiedCache := NewUnifiedCache(config)
	return NewCacheAdapter(unifiedCache)
}
