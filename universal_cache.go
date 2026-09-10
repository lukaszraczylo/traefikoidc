package traefikoidc

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
)

// CacheType defines the type of cache for optimized behavior
type CacheType string

const (
	CacheTypeToken         CacheType = "token"
	CacheTypeBlacklist     CacheType = "blacklist"
	CacheTypeMetadata      CacheType = "metadata"
	CacheTypeIntrospection CacheType = "introspection"
	CacheTypeJWK           CacheType = "jwk"
	CacheTypeSession       CacheType = "session"
	CacheTypeGeneral       CacheType = "general"

	// maxCacheEntrySize defines the maximum size for a single cache entry (64 MiB)
	// This prevents integer overflow when allocating memory for serialization
	maxCacheEntrySize = 64 * 1024 * 1024
)

// UniversalCacheConfig provides configuration for the universal cache
type UniversalCacheConfig struct {
	Strategy          CacheStrategy
	Logger            *Logger
	JWKConfig         *JWKCacheConfig
	MetadataConfig    *MetadataCacheConfig
	TokenConfig       *TokenCacheConfig
	Type              CacheType
	DefaultTTL        time.Duration
	CleanupInterval   time.Duration
	MaxMemoryBytes    int64
	MaxSize           int
	EnableAutoCleanup bool
	EnableMemoryLimit bool
	EnableMetrics     bool
	EnableCompression bool
	SkipAutoCleanup   bool

	// MonotonicMarkers marks a cache whose failed Set must never Delete a
	// pre-existing backend entry for the same key, regardless of the error
	// (FIX-04). Two different caches share this flag, and it does NOT mean
	// their entries are never stale:
	//   - blacklist: a revocation marker is idempotent, so an existing
	//     entry is never stale.
	//   - session invalidation: entries are Unix timestamps compared by
	//     value, so an existing (older) backend entry CAN be stale next
	//     to a newer logout whose Set failed. UniversalCache.Get guards
	//     this by preferring the local value while the key is marked
	//     backend-stale (see UniversalCache.staleBackend).
	MonotonicMarkers bool
}

// TokenCacheConfig provides token-specific cache configuration
type TokenCacheConfig struct {
	BlacklistTTL        time.Duration
	RefreshTokenTTL     time.Duration
	EnableTokenRotation bool
}

// MetadataCacheConfig provides metadata-specific cache configuration
type MetadataCacheConfig struct {
	SecurityCriticalFields         []string
	GracePeriod                    time.Duration
	ExtendedGracePeriod            time.Duration
	MaxGracePeriod                 time.Duration
	SecurityCriticalMaxGracePeriod time.Duration
}

// JWKCacheConfig provides JWK-specific cache configuration
type JWKCacheConfig struct {
	RefreshInterval time.Duration
	MinRefreshTime  time.Duration
	MaxKeyAge       time.Duration
}

// CacheItem represents a single cache entry
type CacheItem struct {
	ExpiresAt    time.Time
	LastAccessed time.Time
	Value        interface{}
	Metadata     map[string]interface{}
	element      *list.Element
	Key          string
	CacheType    CacheType
	Size         int64
	AccessCount  int64
}

// UniversalCache provides a single, unified cache implementation
// that replaces all other cache types
type UniversalCache struct {
	config        UniversalCacheConfig
	ctx           context.Context
	backend       backends.CacheBackend
	logger        *Logger
	lruList       *list.List
	items         map[string]*CacheItem
	cancel        context.CancelFunc
	cleanupTicker *time.Ticker
	wg            sync.WaitGroup
	currentSize   int64
	currentMemory int64
	hits          int64
	misses        int64
	evictions     int64
	mu            sync.RWMutex
	ownsBackend   bool

	// staleBackend marks keys whose backend entry is known to be older than
	// the local one: Set skipped the post-failure Delete for this key
	// (a context deadline/timeout, or a MonotonicMarkers cache) so the
	// backend still holds whatever it had before the failed write. Get
	// prefers the local value over the backend value for a marked key while
	// the local entry is still live AND the mark has not exceeded
	// backendStaleMarkTTL (FIX-04; time-bounded per R4 cache review round 2
	// — see backendStaleLocalValue). The map value is when the key was
	// marked, so the bound can be enforced. Guarded by mu; cleared by
	// removeItem/Clear and by the next successful backend Set for the key.
	staleBackend map[string]time.Time

	// legacyBlacklistMissMu and legacyBlacklistMissUntil bound
	// checkLegacyBlacklistMarker's Redis cost (R4 cache review): a blacklist
	// Get almost always misses, and every miss used to pay for a full
	// legacy-namespace GET (plus PTTL when something happened to be cached
	// there) with no memory of the last attempt. A miss (or a legacy hit
	// that turned out to be a CacheTypeToken claims map, not the boolean
	// marker) is remembered here per key until the deadline, so a repeat
	// blacklist check for the SAME key inside that window skips the legacy
	// lookup entirely. Only meaningful for CacheTypeBlacklist; empty and
	// unused otherwise. Pruned opportunistically by cleanup().
	legacyBlacklistMissMu    sync.Mutex
	legacyBlacklistMissUntil map[string]time.Time
}

// NewUniversalCache creates a new universal cache instance
func NewUniversalCache(config UniversalCacheConfig) *UniversalCache {
	return createUniversalCache(config)
}

// NewUniversalCacheWithBackend creates a new universal cache with a specific backend
func NewUniversalCacheWithBackend(config UniversalCacheConfig, cacheBackend backends.CacheBackend) *UniversalCache {
	cache := createUniversalCache(config)
	cache.backend = cacheBackend
	cache.ownsBackend = false // Shared backend, managed externally
	return cache
}

// createUniversalCache is the internal constructor
func createUniversalCache(config UniversalCacheConfig) *UniversalCache {
	// Apply type-specific defaults first (including MaxSize)
	applyTypeDefaults(&config)

	// Set general defaults only if not already set by type defaults
	if config.MaxSize <= 0 {
		config.MaxSize = 1000
	}
	if config.MaxMemoryBytes <= 0 {
		config.MaxMemoryBytes = 50 * 1024 * 1024 // 50MB default
	}
	if config.DefaultTTL <= 0 {
		config.DefaultTTL = 1 * time.Hour
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 5 * time.Minute
	}
	if config.Logger == nil {
		config.Logger = GetSingletonNoOpLogger()
	}

	ctx, cancel := context.WithCancel(context.Background())

	cache := &UniversalCache{
		items:        make(map[string]*CacheItem),
		lruList:      list.New(),
		config:       config,
		logger:       config.Logger,
		ctx:          ctx,
		cancel:       cancel,
		staleBackend: make(map[string]time.Time),

		legacyBlacklistMissUntil: make(map[string]time.Time),
	}

	// Start cleanup routine only if not skipped
	// When cleanup is managed externally (e.g., by UniversalCacheManager),
	// skip per-cache cleanup to reduce goroutine count
	if !config.SkipAutoCleanup {
		cache.startCleanup()
	}

	return cache
}

// applyTypeDefaults applies type-specific default configurations
func applyTypeDefaults(config *UniversalCacheConfig) {
	switch config.Type {
	case CacheTypeToken:
		if config.TokenConfig == nil {
			config.TokenConfig = &TokenCacheConfig{
				BlacklistTTL:        24 * time.Hour,
				RefreshTokenTTL:     7 * 24 * time.Hour,
				EnableTokenRotation: true,
			}
		}
		if config.MaxSize == 0 {
			config.MaxSize = 5000 // Tokens need more entries
		}

	case CacheTypeMetadata:
		if config.MetadataConfig == nil {
			config.MetadataConfig = &MetadataCacheConfig{
				GracePeriod:                    5 * time.Minute,
				ExtendedGracePeriod:            15 * time.Minute,
				MaxGracePeriod:                 30 * time.Minute,
				SecurityCriticalMaxGracePeriod: 15 * time.Minute,
				SecurityCriticalFields: []string{
					"jwks_uri",
					"token_endpoint",
					"authorization_endpoint",
					"issuer",
				},
			}
		}
		// Only set defaults if not already specified
		if config.MaxSize == 0 {
			config.MaxSize = 100 // Fewer providers
		}
		if config.DefaultTTL == 0 {
			config.DefaultTTL = 1 * time.Hour
		}

	case CacheTypeJWK:
		if config.JWKConfig == nil {
			config.JWKConfig = &JWKCacheConfig{
				RefreshInterval: 1 * time.Hour,
				MinRefreshTime:  5 * time.Minute,
				MaxKeyAge:       24 * time.Hour,
			}
		}
		if config.MaxSize == 0 {
			config.MaxSize = 200 // Limited number of keys
		}
		if config.DefaultTTL == 0 {
			config.DefaultTTL = 1 * time.Hour
		}

	case CacheTypeSession:
		if config.MaxSize == 0 {
			config.MaxSize = 10000 // Many concurrent sessions
		}
		if config.DefaultTTL == 0 {
			config.DefaultTTL = 30 * time.Minute
		}

	default:
		// General cache defaults already set
	}
}

// Set stores a value in the cache
func (c *UniversalCache) Set(key string, value interface{}, ttl time.Duration) error {
	// Only use default TTL if ttl is exactly zero (not specified)
	// Negative TTL means the item should expire in the past
	if ttl == 0 {
		ttl = c.config.DefaultTTL
	}

	// If we have a backend, use it for distributed caching
	if c.backend != nil {
		// Serialize the value
		data, err := c.serialize(value)
		if err != nil {
			c.logger.Errorf("Failed to serialize value for key %s: %v", key, err)
			return err
		}

		// Store in backend
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		if err := c.backend.Set(ctx, c.prefixKey(key), data, ttl); err != nil {
			c.logger.Infof("Backend set error for key %s: %v", key, err)
			// The backend still holds an OLDER entry for this key. If we
			// leave it in place, a subsequent Get treats the backend as
			// authoritative and (via updateLocalCache) overwrites the
			// just-written local value with the stale one (R162). Evict the
			// stale backend entry so Get falls through to the fresh local
			// value instead of resurrecting the old one.
			//
			// Two cases must NOT evict (FIX-04):
			//   - A context deadline/timeout error: the SET may have reached
			//     Redis and applied after the client gave up waiting for the
			//     reply. Deleting here would erase a write that actually
			//     landed.
			//   - MonotonicMarkers caches (blacklist, session invalidation):
			//     deleting a pre-existing entry on any failed Set risks
			//     erasing a marker another replica still needs.
			//
			// Either way, the backend entry the next Get sees for this key
			// may be older than the local write just made (skipping the
			// Delete does not make the old entry disappear, and for
			// MonotonicMarkers it can be a genuinely older value, not only
			// a survived write). Mark the key backend-stale so Get prefers
			// the fresh local value instead of resurrecting the old one.
			if !c.config.MonotonicMarkers && !isTimeoutOrDeadlineError(err) {
				dctx, dcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				if _, derr := c.backend.Delete(dctx, c.prefixKey(key)); derr != nil {
					c.logger.Debugf("Backend delete after failed set for key %s: %v", key, derr)
				}
				dcancel()
			} else {
				c.markBackendStale(key)
			}
		} else {
			c.clearBackendStale(key)
		}
	}

	return c.setLocal(key, value, ttl)
}

// SetLocal stores a value only in the in-memory LRU, bypassing any
// distributed backend. Use for values that don't survive JSON round-tripping
// — interfaces holding concrete crypto keys, *big.Int, or types whose
// unexported fields yaegi exposes under an X prefix on Marshal. Each replica
// caches independently; correctness must not depend on cross-replica
// coherence for these keys.
func (c *UniversalCache) SetLocal(key string, value interface{}, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.config.DefaultTTL
	}
	return c.setLocal(key, value, ttl)
}

// setLocal performs the in-memory portion of a write. ttl must already be
// resolved against DefaultTTL by the caller.
func (c *UniversalCache) setLocal(key string, value interface{}, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLocalLocked(key, value, ttl)
	return nil
}

// setLocalLocked performs the in-memory write. Caller must already hold
// c.mu — extracted from setLocal so SetIfAbsent can run its presence check
// and this insert inside a single critical section (FIX-17), rather than
// setLocal re-acquiring c.mu itself.
func (c *UniversalCache) setLocalLocked(key string, value interface{}, ttl time.Duration) {
	size := c.estimateSize(value)

	// For an existing key the replace below frees the OLD value's size, so the
	// memory cap should only be checked against the NET growth (new - old), not
	// the full new size while currentMemory still holds the old size. Using the
	// full size here over-triggers eviction and drops live entries that would
	// have fit once the old value was released.
	growth := size
	if existing, exists := c.items[key]; exists {
		growth = size - existing.Size
	}

	// Check memory limits
	if c.config.MaxMemoryBytes > 0 {
		// Evict items if necessary to make room
		for c.currentMemory+growth > c.config.MaxMemoryBytes && c.lruList.Len() > 0 {
			c.evictOldest()
		}
	}

	// Check size limits — only evict when inserting a NEW key. An in-place
	// update of an existing key adds no net entry, so evicting would drop an
	// unrelated live LRU entry and leave the cache one below capacity (cache
	// thrashes under sustained traffic at MaxSize). Mirror of the shard
	// backend fix (R139 F2).
	if _, present := c.items[key]; !present && c.lruList.Len() >= c.config.MaxSize {
		c.evictOldest()
	}

	// Update or create item
	now := time.Now()
	if existing, exists := c.items[key]; exists {
		// Update existing item
		c.currentMemory -= existing.Size
		c.lruList.Remove(existing.element)

		existing.Value = value
		existing.Size = size
		existing.ExpiresAt = now.Add(ttl)
		existing.LastAccessed = now
		existing.AccessCount++

		// Move to front
		existing.element = c.lruList.PushFront(key)
		c.currentMemory += size
	} else {
		// Create new item
		item := &CacheItem{
			Key:          key,
			Value:        value,
			Size:         size,
			ExpiresAt:    now.Add(ttl),
			LastAccessed: now,
			AccessCount:  1,
			CacheType:    c.config.Type,
			Metadata:     make(map[string]interface{}),
		}

		item.element = c.lruList.PushFront(key)
		c.items[key] = item

		c.currentSize++
		c.currentMemory += size
	}

	if c.logger.IsDebug() {
		c.logger.Debugf("UniversalCache[%s]: Set key=%s, ttl=%v, size=%d bytes",
			c.config.Type, key, ttl, size)
	}
}

// backendSetNXer is the optional distributed check-and-set primitive a
// CacheBackend can provide: RedisBackend implements it via Redis SET key
// value NX PX <ttl-ms>, and resilience.CircuitBreakerBackend /
// resilience.HealthCheckBackend forward to it when the backend they wrap
// does (FIX-17 round-2). CacheBackend itself is not widened to require it —
// every other implementer and test double would need a method only
// SetIfAbsent needs — so SetIfAbsent reaches it through this type
// assertion instead (FIX-17).
type backendSetNXer interface {
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
}

// errSetIfAbsentUnsupported is returned by SetIfAbsent when a distributed
// backend is attached but does not (even transitively, through a wrapper)
// implement backendSetNXer. Round-2 correction: this used to silently fall
// back to setIfAbsentLocal instead, which is safe only when every caller
// sharing the key is in this same process. For a distributed cache — the
// whole point of attaching a backend — two replicas each taking the
// local-only path both observe "absent" and both claim, exactly the
// double-accept FIX-17 exists to close (this is what happened before
// resilience.CircuitBreakerBackend/HealthCheckBackend gained a SetNX
// passthrough). Erroring loudly instead lets a caller like
// checkAndMarkLogoutJTIProcessed fall through to its own shared-backend
// Get+Set fallback rather than get a false "claimed" from either replica.
//
// Compared with == only: no errors.As, no fmt.Errorf %w — an interpreted
// value wrapped with %w loses its type under yaegi v0.16.1, and errors.As
// with an interpreted target type panics there.
var errSetIfAbsentUnsupported = errors.New("cache backend does not support atomic SetIfAbsent")

// SetIfAbsent atomically stores value under key only if key is not already
// present, and reports whether THIS call performed the store. It replaces
// the TOCTOU-prone pattern of a separate Get followed by a Set with one
// atomic check-and-set (FIX-17, R36 correction).
//
// With no distributed backend attached, the check and the insert happen
// inside a single c.mu critical section, so concurrent SetIfAbsent callers
// racing the same key in this process can never both observe "absent".
//
// With a backend attached that implements the optional backendSetNXer
// primitive (RedisBackend does, and so do the circuit-breaker/health-check
// wrappers when the backend underneath does), that call is the sole source
// of truth for "did this claim the key", so the check is atomic across
// every replica sharing that backend too — closing the gap
// backchannelLogoutJTIMu's process-local mutex could never cover. A
// successful backend claim is then mirrored into the local cache as a
// best-effort read-through; a failure to mirror it does not change the
// (already-correct) return value.
//
// A backend that does not implement backendSetNXer at all returns
// errSetIfAbsentUnsupported instead of falling back to the local-only path
// (FIX-17 round-2): the local-only path is correct only within this
// process, and silently taking it for an attached distributed backend lets
// two replicas both observe "absent" and both claim.
func (c *UniversalCache) SetIfAbsent(key string, value interface{}, ttl time.Duration) (bool, error) {
	if ttl == 0 {
		ttl = c.config.DefaultTTL
	}

	if c.backend != nil {
		nx, ok := c.backend.(backendSetNXer)
		if !ok {
			c.logger.Debugf("SetIfAbsent: backend for key %s does not support atomic SetNX; caller must use its own shared-backend fallback", key)
			return false, errSetIfAbsentUnsupported
		}
		return c.setIfAbsentBackend(nx, key, value, ttl)
	}

	return c.setIfAbsentLocal(key, value, ttl)
}

// setIfAbsentBackend claims key in the distributed backend first — the one
// operation every replica shares — then mirrors a successful claim into the
// local cache. The mirror is best-effort: if it fails, the backend claim
// still stands and this call still correctly reports true.
func (c *UniversalCache) setIfAbsentBackend(nx backendSetNXer, key string, value interface{}, ttl time.Duration) (bool, error) {
	data, err := c.serialize(value)
	if err != nil {
		c.logger.Errorf("SetIfAbsent: failed to serialize value for key %s: %v", key, err)
		return false, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	claimed, err := nx.SetNX(ctx, c.prefixKey(key), data, ttl)
	cancel()
	if err != nil {
		c.logger.Infof("SetIfAbsent: backend SetNX error for key %s: %v", key, err)
		return false, err
	}
	if !claimed {
		return false, nil
	}
	if lerr := c.setLocal(key, value, ttl); lerr != nil {
		c.logger.Debugf("SetIfAbsent: local mirror failed for key %s: %v", key, lerr)
	}
	return true, nil
}

// setIfAbsentLocal performs the presence check and the insert inside one
// c.mu critical section, so no other Set/SetIfAbsent call on this cache can
// interleave between them.
func (c *UniversalCache) setIfAbsentLocal(key string, value interface{}, ttl time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, exists := c.items[key]; exists && !time.Now().After(existing.ExpiresAt) {
		return false, nil
	}

	c.setLocalLocked(key, value, ttl)
	return true, nil
}

// Get retrieves a value from the cache
func (c *UniversalCache) Get(key string) (interface{}, bool) {
	// Try backend first if available (for distributed consistency)
	if c.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		data, ttl, exists, err := c.backend.Get(ctx, c.prefixKey(key))
		if err != nil {
			c.logger.Debugf("Backend get error for key %s: %v", key, err)
			// Fall through to local cache
		} else if exists {
			// Deserialize the value
			var value interface{}
			if err := c.deserialize(data, &value); err != nil {
				c.logger.Errorf("Failed to deserialize value for key %s: %v", key, err)
				// Fall through to local cache
			} else if localValue, stale := c.backendStaleLocalValue(key); stale && !(c.config.MonotonicMarkers && backendValueIsNewer(value, localValue)) {
				// A prior Set skipped the Delete for this key (FIX-04) and
				// the backend entry may be older than the local one — for a
				// MonotonicMarkers cache (session invalidation) it can be a
				// genuinely older, meaningfully different value, not only a
				// survived write. Serve the fresher local value instead and
				// do not let updateLocalCache overwrite it with the stale
				// backend one.
				//
				// backendValueIsNewer guards the other direction (R4 cache
				// review) for a MonotonicMarkers cache ONLY (R4 cache review
				// round 2, minor, universal_cache.go:546): the mark only
				// records "this replica's own write may not have landed",
				// not "the backend can never be ahead". A DIFFERENT replica
				// can write a genuinely newer value to the same key (e.g. a
				// later cross-replica backchannel logout) while this key is
				// still marked stale here. For a MonotonicMarkers cache,
				// when both values decode to a comparable timestamp and the
				// backend's is not older, trust it instead of pinning this
				// replica's stale local one. Gated on MonotonicMarkers
				// because a plain numeric cache has no such guarantee that
				// "larger" means "newer" — trusting it there risks the exact
				// clobber FIX-04 exists to prevent. Every other cache (and
				// every value backendValueIsNewer cannot compare, e.g. the
				// blacklist cache's bool markers or a string/map/struct
				// value) instead recovers once the mark itself ages out —
				// see backendStaleLocalValue's backendStaleMarkTTL bound.
				atomic.AddInt64(&c.hits, 1)
				return localValue, true
			} else {
				atomic.AddInt64(&c.hits, 1)
				// Re-populate local cache with the backend entry's REAL remaining
				// TTL, not the federated DefaultTTL, so the in-memory copy
				// cannot outlive the authoritative backend entry. Previously a
				// short-TTL backend value (e.g. a 5-minute token) was cached
				// locally for up to DefaultTTL (often 1h); if the backend then
				// became unreachable, getLocal kept serving it well past its
				// intended expiry.
				//
				// ttl==backends.NoExpiryTTL means the backend key genuinely has
				// no expiry (Redis PTTL -1): federate DefaultTTL, same as
				// before. Any other non-positive ttl means the backend key is
				// expiring now or already gone (FIX-31) — serve this read, but
				// do not repopulate the local copy: caching it for DefaultTTL
				// would keep serving the value locally long after the backend
				// expires it (R59), up to 25h for the session-invalidation
				// cache.
				switch {
				case ttl == backends.NoExpiryTTL:
					_ = c.updateLocalCache(key, value, c.config.DefaultTTL)
				case ttl > 0:
					_ = c.updateLocalCache(key, value, ttl)
				}
				return value, true
			}
		} else if c.config.Type == CacheTypeBlacklist {
			// R128 renamed the blacklist backend namespace from
			// CacheTypeToken's "token:" prefix to CacheTypeBlacklist's
			// "blacklist:" prefix with no migration. For one release, a
			// miss on the new namespace also checks the legacy "token:"
			// namespace so revocations written before the upgrade (TTL up
			// to 24h, see token_manager.go blacklistDuration) keep denying
			// already-issued tokens (FIX-16). This shim works in ONE
			// direction only: an upgraded replica keeps honoring
			// revocations a pre-upgrade replica wrote under "token:". A
			// pre-upgrade replica has no knowledge of "blacklist:" and so
			// does NOT see revocations an upgraded replica writes during
			// the same rolling deploy. Writes stay on the new namespace
			// only (see Set/prefixKey).
			if blacklisted, ok := c.checkLegacyBlacklistMarker(ctx, key); ok {
				atomic.AddInt64(&c.hits, 1)
				_ = c.updateLocalCache(key, blacklisted, c.config.DefaultTTL)
				return blacklisted, true
			}
		}
	}

	return c.getLocal(key)
}

// GetLocal retrieves a value only from the in-memory LRU, never querying the
// distributed backend. Pair with SetLocal for values that aren't safe to
// serialize (see SetLocal docstring).
func (c *UniversalCache) GetLocal(key string) (interface{}, bool) {
	return c.getLocal(key)
}

// getLocal returns the in-memory entry for key honoring expiry, grace
// periods, and the RLock fast path used by token/JWK/session/introspection/
// blacklist caches.
func (c *UniversalCache) getLocal(key string) (interface{}, bool) {
	// Fast read path for caches whose eviction is dominated by TTL rather than
	// access-recency (token, JWK, session, introspection, blacklist). Holding
	// only an RLock here lets all concurrent readers verify cached tokens in
	// parallel — under yaegi the previous unconditional Lock serialized every
	// JWT verify on a single mutex and pinned a CPU under load.
	switch c.config.Type {
	case CacheTypeToken, CacheTypeJWK, CacheTypeSession, CacheTypeIntrospection, CacheTypeBlacklist:
		c.mu.RLock()
		item, exists := c.items[key]
		if !exists {
			c.mu.RUnlock()
			atomic.AddInt64(&c.misses, 1)
			return nil, false
		}
		if !time.Now().After(item.ExpiresAt) {
			value := item.Value
			c.mu.RUnlock()
			atomic.AddInt64(&c.hits, 1)
			return value, true
		}
		c.mu.RUnlock()
		// Expired — return miss immediately. The periodic cleanup goroutine
		// will evict the stale entry. NEVER fall through to the write-locked
		// slow path for Token/JWK/Session caches: under Yaegi the write Lock
		// at line 403 costs 10-100ms per acquisition, and Go's RWMutex
		// writer-priority semantics block ALL new RLock callers while a Lock
		// is pending. A single expired-token event turns every concurrent
		// request from read-parallel into write-serialized — the exact
		// convoy that produced the 737-goroutine pileup at 0x400275a608.
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	item, exists := c.items[key]
	if !exists {
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	// Check expiration
	now := time.Now()
	if now.After(item.ExpiresAt) {
		// For metadata cache, check if we should apply grace period
		// Grace periods are only extended if explicitly marked or if this is a retry after failure
		if c.config.Type == CacheTypeMetadata && c.config.MetadataConfig != nil {
			// Check if grace period has been explicitly activated (e.g., due to provider outage)
			if gracePeriod, ok := item.Metadata["grace_period_active"].(bool); ok && gracePeriod {
				if c.shouldExtendGracePeriod(item, now) {
					newExpiry := c.calculateNewExpiry(item, now)
					item.ExpiresAt = newExpiry
					c.logger.Infof("UniversalCache[%s]: Extended grace period for key=%s until %v",
						c.config.Type, key, newExpiry)
					// Continue to return the cached value during grace period
				} else {
					// Grace period has expired completely
					c.removeItem(key, item)
					atomic.AddInt64(&c.misses, 1)
					return nil, false
				}
			} else {
				// No grace period active, remove expired item
				c.removeItem(key, item)
				atomic.AddInt64(&c.misses, 1)
				return nil, false
			}
		} else {
			// Non-metadata cache or no grace period config
			c.removeItem(key, item)
			atomic.AddInt64(&c.misses, 1)
			return nil, false
		}
	}

	// Update access time and count
	item.LastAccessed = now
	item.AccessCount++

	// Move to front of LRU
	c.lruList.MoveToFront(item.element)

	atomic.AddInt64(&c.hits, 1)
	return item.Value, true
}

// Delete removes a key from the cache
func (c *UniversalCache) Delete(key string) bool {
	// Delete from backend if available
	if c.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		if _, err := c.backend.Delete(ctx, c.prefixKey(key)); err != nil {
			c.logger.Debugf("Backend delete error for key %s: %v", key, err)
			// Continue with local delete
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	item, exists := c.items[key]
	if !exists {
		return false
	}

	c.removeItem(key, item)
	return true
}

// Clear removes all items from the cache
func (c *UniversalCache) Clear() {
	// Clear backend if available
	if c.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		if err := c.backend.Clear(ctx); err != nil {
			c.logger.Infof("Backend clear error: %v", err)
			// Continue with local clear
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*CacheItem)
	c.staleBackend = make(map[string]time.Time)
	c.lruList.Init()
	c.currentSize = 0
	c.currentMemory = 0

	c.logger.Debugf("UniversalCache[%s]: Cleared all items", c.config.Type)
}

// Size returns the number of items in the cache
func (c *UniversalCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return int(c.currentSize)
}

// MemoryUsage returns the current memory usage in bytes
func (c *UniversalCache) MemoryUsage() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentMemory
}

// GetMetrics returns cache metrics
func (c *UniversalCache) GetMetrics() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hitRate := float64(0)
	total := atomic.LoadInt64(&c.hits) + atomic.LoadInt64(&c.misses)
	if total > 0 {
		hitRate = float64(atomic.LoadInt64(&c.hits)) / float64(total)
	}

	return map[string]interface{}{
		"type":       c.config.Type,
		"size":       c.currentSize,
		"entries":    c.currentSize, // Alias for backward compatibility
		"memory":     c.currentMemory,
		"hits":       atomic.LoadInt64(&c.hits),
		"misses":     atomic.LoadInt64(&c.misses),
		"evictions":  atomic.LoadInt64(&c.evictions),
		"hit_rate":   hitRate,
		"max_size":   c.config.MaxSize,
		"max_memory": c.config.MaxMemoryBytes,
	}
}

// Cleanup manually triggers cleanup of expired items
func (c *UniversalCache) Cleanup() {
	c.cleanup()
}

// Close shuts down the cache
func (c *UniversalCache) Close() error {
	c.cancel()

	// Stop cleanup ticker
	if c.cleanupTicker != nil {
		c.cleanupTicker.Stop()
	}

	// Wait for cleanup routine to finish with timeout
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Cleanup routine finished normally
	case <-time.After(2 * time.Second):
		// Timeout waiting for cleanup routine
		c.logger.Debug("UniversalCache[%s]: Timeout waiting for cleanup routine", c.config.Type)
	}

	// Clear all items
	c.Clear()

	// Close backend only if this cache owns it (not shared)
	if c.backend != nil && c.ownsBackend {
		if err := c.backend.Close(); err != nil {
			c.logger.Infof("Failed to close cache backend: %v", err)
		}
	}

	c.logger.Debugf("UniversalCache[%s]: Closed", c.config.Type)
	return nil
}

// removeItem removes an item from the cache (must be called with lock held)
func (c *UniversalCache) removeItem(key string, item *CacheItem) {
	delete(c.items, key)
	delete(c.staleBackend, key)
	c.lruList.Remove(item.element)
	c.currentSize--
	c.currentMemory -= item.Size
}

// evictOldest evicts the oldest item from the cache (must be called with lock held)
func (c *UniversalCache) evictOldest() {
	elem := c.lruList.Back()
	if elem == nil {
		return
	}
	key, _ := elem.Value.(string) // Safe to ignore: cache internal type assertion
	if item, exists := c.items[key]; exists && item.element == elem {
		c.removeItem(key, item)
		atomic.AddInt64(&c.evictions, 1)
		if c.logger.IsDebug() {
			c.logger.Debugf("UniversalCache[%s]: Evicted key=%s", c.config.Type, key)
		}
		return
	}
	// Defensive forward-progress guard: the back node is dangling — its key is
	// absent from c.items, or c.items[key] points at a newer node (a stale
	// duplicate). Drop the node directly so an eviction loop
	// (`for ... && c.lruList.Len() > 0`) is guaranteed to terminate and can
	// never spin holding c.mu.Lock(). With the updateLocalCache replace-in-place
	// fix this branch should be unreachable, but it makes the spin impossible.
	c.lruList.Remove(elem)
	if c.currentSize > 0 {
		c.currentSize--
	}
}

// SetMaxSize sets the maximum size and evicts items if necessary
func (c *UniversalCache) SetMaxSize(newSize int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldSize := c.config.MaxSize
	c.config.MaxSize = newSize

	// If the new size is smaller, evict items until we meet the new limit
	if newSize < oldSize {
		for c.lruList.Len() > newSize {
			c.evictOldest()
		}
		c.logger.Infof("UniversalCache[%s]: Resized from %d to %d, evicted %d items",
			c.config.Type, oldSize, newSize, oldSize-c.lruList.Len())
	}
}

// ActivateGracePeriod activates grace period for a specific key (e.g., due to provider outage)
func (c *UniversalCache) ActivateGracePeriod(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if item, exists := c.items[key]; exists {
		item.Metadata["grace_period_active"] = true
		c.logger.Infof("UniversalCache[%s]: Activated grace period for key=%s", c.config.Type, key)
	}
}

// startCleanup starts the background cleanup routine
func (c *UniversalCache) startCleanup() {
	c.cleanupTicker = time.NewTicker(c.config.CleanupInterval)
	c.wg.Add(1)

	go func() {
		defer c.wg.Done()

		for {
			select {
			case <-c.ctx.Done():
				return
			case <-c.cleanupTicker.C:
				c.cleanup()
			}
		}
	}()
}

// cleanup removes expired items from the cache
func (c *UniversalCache) cleanup() {
	now := time.Now()
	c.pruneLegacyBlacklistMisses(now)

	c.mu.Lock()
	defer c.mu.Unlock()

	var toRemove []string

	for key, item := range c.items {
		if now.After(item.ExpiresAt) {
			// Special handling for metadata cache grace periods
			if c.config.Type == CacheTypeMetadata && c.config.MetadataConfig != nil {
				// Only keep items that have active grace period and are still within limits
				if gracePeriod, ok := item.Metadata["grace_period_active"].(bool); ok && gracePeriod {
					if !c.shouldExtendGracePeriod(item, now) {
						toRemove = append(toRemove, key)
					}
				} else {
					// No grace period active, remove expired item
					toRemove = append(toRemove, key)
				}
			} else {
				toRemove = append(toRemove, key)
			}
		}
	}

	for _, key := range toRemove {
		if item, exists := c.items[key]; exists {
			c.removeItem(key, item)
		}
	}

	if len(toRemove) > 0 {
		c.logger.Debugf("UniversalCache[%s]: Cleaned up %d expired items",
			c.config.Type, len(toRemove))
	}
}

// estimateSize estimates the memory size of a value
func (c *UniversalCache) estimateSize(value interface{}) int64 {
	// Basic size estimation - can be enhanced based on type
	switch v := value.(type) {
	case string:
		return int64(len(v))
	case []byte:
		return int64(len(v))
	case map[string]interface{}:
		// Rough estimate for maps
		return int64(len(v) * 100)
	default:
		// Default estimate
		return 64
	}
}

// shouldExtendGracePeriod determines if grace period should be extended
func (c *UniversalCache) shouldExtendGracePeriod(item *CacheItem, now time.Time) bool {
	if c.config.MetadataConfig == nil {
		return false
	}

	// Check if we're within the maximum grace period
	maxGrace := c.config.MetadataConfig.MaxGracePeriod

	// Check if this is a security-critical field
	if fieldName, ok := item.Metadata["field"].(string); ok {
		for _, critical := range c.config.MetadataConfig.SecurityCriticalFields {
			if fieldName == critical {
				maxGrace = c.config.MetadataConfig.SecurityCriticalMaxGracePeriod
				break
			}
		}
	}

	// Calculate how long since the item originally expired
	timeSinceExpiry := now.Sub(item.ExpiresAt)
	return timeSinceExpiry <= maxGrace
}

// calculateNewExpiry calculates the new expiry time with progressive grace periods
func (c *UniversalCache) calculateNewExpiry(item *CacheItem, now time.Time) time.Time {
	if c.config.MetadataConfig == nil {
		return now.Add(c.config.DefaultTTL)
	}

	// Progressive grace period based on access count
	var gracePeriod time.Duration
	switch {
	case item.AccessCount < 5:
		gracePeriod = c.config.MetadataConfig.GracePeriod
	case item.AccessCount < 10:
		gracePeriod = c.config.MetadataConfig.ExtendedGracePeriod
	default:
		gracePeriod = c.config.MetadataConfig.MaxGracePeriod
	}

	// Apply security limits
	if fieldName, ok := item.Metadata["field"].(string); ok {
		for _, critical := range c.config.MetadataConfig.SecurityCriticalFields {
			if fieldName == critical && gracePeriod > c.config.MetadataConfig.SecurityCriticalMaxGracePeriod {
				gracePeriod = c.config.MetadataConfig.SecurityCriticalMaxGracePeriod
				break
			}
		}
	}

	return now.Add(gracePeriod)
}

// Type-specific helper methods

// SetWithMetadata sets a value with additional metadata
func (c *UniversalCache) SetWithMetadata(key string, value interface{}, ttl time.Duration, metadata map[string]interface{}) error {
	err := c.Set(key, value, ttl)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if item, exists := c.items[key]; exists {
		for k, v := range metadata {
			item.Metadata[k] = v
		}
	}

	return nil
}

// TokenCacheOperations provides token-specific operations
func (c *UniversalCache) BlacklistToken(token string, ttl time.Duration) error {
	if c.config.Type != CacheTypeToken {
		return fmt.Errorf("blacklist operation only available for token cache")
	}

	if ttl <= 0 && c.config.TokenConfig != nil {
		ttl = c.config.TokenConfig.BlacklistTTL
	}

	return c.SetWithMetadata(token, true, ttl, map[string]interface{}{
		"blacklisted":    true,
		"blacklisted_at": time.Now(),
	})
}

// IsTokenBlacklisted checks if a token is blacklisted
func (c *UniversalCache) IsTokenBlacklisted(token string) bool {
	if c.config.Type != CacheTypeToken {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if item, exists := c.items[token]; exists {
		if blacklisted, ok := item.Metadata["blacklisted"].(bool); ok {
			return blacklisted
		}
	}

	return false
}

// Getters for backward compatibility with tests

// Mutex returns the cache mutex for backward compatibility
func (c *UniversalCache) Mutex() *sync.RWMutex {
	return &c.mu
}

// Strategy returns the cache strategy for backward compatibility
func (c *UniversalCache) Strategy() CacheStrategy {
	return c.config.Strategy
}

// serialize converts a value to bytes for backend storage
func (c *UniversalCache) serialize(value interface{}) ([]byte, error) {
	// If value is already a byte slice (e.g., pre-marshaled JSON from metadata_cache),
	// store it directly with a marker to prevent double-encoding.
	// This fixes the issue where []byte was being JSON-marshaled, causing Base64 encoding.
	if bytes, ok := value.([]byte); ok {
		// Validate size to prevent integer overflow
		if len(bytes) > maxCacheEntrySize {
			return nil, fmt.Errorf("cache entry size %d exceeds maximum allowed size %d", len(bytes), maxCacheEntrySize)
		}
		// Check for potential overflow when adding marker byte
		if len(bytes) == maxCacheEntrySize {
			return nil, fmt.Errorf("cache entry size would overflow when adding marker byte")
		}

		// Prepend marker byte 0x00 to indicate raw bytes (not JSON-encoded)
		result := make([]byte, len(bytes)+1)
		result[0] = 0x00
		copy(result[1:], bytes)
		return result, nil
	}

	// For all other types (maps, strings, etc.), use JSON encoding
	// Prepend marker byte 0x01 to indicate JSON-encoded data
	jsonData, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	// Validate size to prevent integer overflow
	if len(jsonData) > maxCacheEntrySize {
		return nil, fmt.Errorf("serialized cache entry size %d exceeds maximum allowed size %d", len(jsonData), maxCacheEntrySize)
	}
	// Check for potential overflow when adding marker byte
	if len(jsonData) == maxCacheEntrySize {
		return nil, fmt.Errorf("serialized cache entry size would overflow when adding marker byte")
	}

	result := make([]byte, len(jsonData)+1)
	result[0] = 0x01
	copy(result[1:], jsonData)
	return result, nil
}

// deserialize converts bytes from backend storage to a value
func (c *UniversalCache) deserialize(data []byte, value interface{}) error {
	if len(data) == 0 {
		return fmt.Errorf("cannot deserialize empty data")
	}

	// Check for type marker (added by serialize)
	if data[0] == 0x00 {
		// Raw bytes - strip marker and return as-is
		rawBytes := data[1:]
		if ptr, ok := value.(*interface{}); ok {
			*ptr = rawBytes
			return nil
		}
		return fmt.Errorf("cannot deserialize raw bytes into %T", value)
	}

	if data[0] == 0x01 {
		// JSON-encoded - strip marker and unmarshal
		return json.Unmarshal(data[1:], value)
	}

	// Legacy data without marker (for backward compatibility)
	// Try to unmarshal as JSON
	if err := json.Unmarshal(data, value); err != nil {
		// If unmarshal fails, treat as raw bytes
		if ptr, ok := value.(*interface{}); ok {
			*ptr = data
			return nil
		}
		return err
	}
	return nil
}

// prefixKey adds a cache type prefix to the key for backend storage
func (c *UniversalCache) prefixKey(key string) string {
	return fmt.Sprintf("%s:%s", c.config.Type, key)
}

// legacyBlacklistPrefix is the backend key prefix blacklist entries were
// written under before the R128 rename (CacheTypeToken's "token:" prefix;
// see newBlacklistCacheConfig in universal_cache_singleton.go). Used only
// by checkLegacyBlacklistMarker (FIX-16).
const legacyBlacklistPrefix = "token:"

// legacyBlacklistMissCacheTTL bounds how long checkLegacyBlacklistMarker
// remembers that a key missed the legacy namespace before it will ask Redis
// about that same key again (R4 cache review). A blacklist Get almost
// always misses — most tokens are never revoked — so without this bound
// every single blacklist check paid for an extra Redis round trip, forever,
// on the verify hot path. A legacy marker still present in Redis when the
// window ends is honored on the next check; this only stops re-asking for
// the SAME key more than once per window while nothing has changed.
const legacyBlacklistMissCacheTTL = 30 * time.Second

// legacyBlacklistTrueMarker is the exact byte encoding UniversalCache.
// serialize(true) produces: marker byte 0x01 (JSON-encoded) followed by
// json.Marshal(true). checkLegacyBlacklistMarker compares the raw legacy
// value against this directly so it can reject the common case — a
// CacheTypeToken claims map cached under the same raw token — without
// JSON-decoding the whole map just to learn it isn't a bool (R4 cache
// review: that decode ran on the verify hot path for every cached token).
var legacyBlacklistTrueMarker = []byte{0x01, 't', 'r', 'u', 'e'}

// checkLegacyBlacklistMarker reads a blacklist marker under the pre-R128
// "token:" namespace. Only a stored boolean true counts as blacklisted — a
// CacheTypeToken entry for the same raw token is a cached claims map, never
// the boolean revocation marker, and must not be misread as one (FIX-16).
func (c *UniversalCache) checkLegacyBlacklistMarker(ctx context.Context, key string) (bool, bool) {
	if c.legacyBlacklistRecentlyMissed(key) {
		return false, false
	}

	data, _, exists, err := c.backend.Get(ctx, legacyBlacklistPrefix+key)
	if err != nil || !exists {
		c.recordLegacyBlacklistMiss(key)
		return false, false
	}

	if bytesEqual(data, legacyBlacklistTrueMarker) {
		return true, true
	}

	// Anything else is not the boolean marker — most commonly a
	// CacheTypeToken claims map for this same raw token, always larger than
	// the 5-byte marker could ever be. Remember the miss either way so the
	// next check for this key skips the round trip too.
	c.recordLegacyBlacklistMiss(key)
	return false, false
}

// bytesEqual reports whether a and b hold the same bytes. A small local
// helper rather than importing "bytes" for one comparison.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// legacyBlacklistRecentlyMissed reports whether key's legacy-namespace
// lookup is still inside its remembered miss window.
func (c *UniversalCache) legacyBlacklistRecentlyMissed(key string) bool {
	c.legacyBlacklistMissMu.Lock()
	defer c.legacyBlacklistMissMu.Unlock()
	until, ok := c.legacyBlacklistMissUntil[key]
	return ok && time.Now().Before(until)
}

// recordLegacyBlacklistMiss remembers that key's legacy-namespace lookup
// just missed (or found something other than the boolean marker), so the
// next checkLegacyBlacklistMarker call for it skips Redis until the window
// elapses.
func (c *UniversalCache) recordLegacyBlacklistMiss(key string) {
	c.legacyBlacklistMissMu.Lock()
	c.legacyBlacklistMissUntil[key] = time.Now().Add(legacyBlacklistMissCacheTTL)
	c.legacyBlacklistMissMu.Unlock()
}

// pruneLegacyBlacklistMisses drops expired entries so
// legacyBlacklistMissUntil does not grow without bound over the life of the
// process. Called from cleanup(), which already runs on a timer for every
// cache (including CacheTypeBlacklist, whose cleanup is externally managed
// but still periodically invoked — see UniversalCacheManager).
func (c *UniversalCache) pruneLegacyBlacklistMisses(now time.Time) {
	c.legacyBlacklistMissMu.Lock()
	defer c.legacyBlacklistMissMu.Unlock()
	for key, until := range c.legacyBlacklistMissUntil {
		if !now.Before(until) {
			delete(c.legacyBlacklistMissUntil, key)
		}
	}
}

// isTimeoutOrDeadlineError reports whether err indicates the backend
// operation's outcome is unknown because the caller's context expired or a
// network timeout fired, rather than the operation genuinely failing. In
// that case the write may have reached the backend and applied after the
// client gave up waiting for the reply (FIX-04).
func isTimeoutOrDeadlineError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// backendStaleMarkTTL bounds how long a backend-stale mark (markBackendStale)
// can pin the local value over the backend one (R4 cache review round 2).
// FIX-04 assumed the backend value could only ever be OLDER than the local
// one — true for a same-replica write that may have landed after a timeout
// — and originally let the mark stand for as long as the local entry stayed
// live (up to DefaultTTL, e.g. 25h for session invalidation, 100*365 days
// for the DCR credentials cache). That let a mark pin a stale local value
// over a genuinely NEWER value a different replica wrote, for any value type
// backendValueIsNewer cannot compare (strings, maps, structs — the numeric
// newer-wins comparison only ever applies to MonotonicMarkers caches; see
// UniversalCache.Get). Bounding the mark keeps the original timeout-race
// protection (500ms Set timeout plus generous margin for the write to land)
// while guaranteeing a later cross-replica write is not ignored forever.
// A package-level var, not a const, so tests can shrink it instead of
// sleeping for the production value.
var backendStaleMarkTTL = 5 * time.Second

// markBackendStale records that the backend entry for key may be older than
// the local one, because Set just skipped the post-failure Delete for it
// (FIX-04). Get consults this to avoid serving the stale backend value over
// a live local entry, for up to backendStaleMarkTTL.
func (c *UniversalCache) markBackendStale(key string) {
	c.mu.Lock()
	c.staleBackend[key] = time.Now()
	c.mu.Unlock()
}

// clearBackendStale removes the backend-stale mark for key, called after a
// backend Set for it succeeds: the backend now holds the latest value, so
// Get can trust it again.
func (c *UniversalCache) clearBackendStale(key string) {
	c.mu.Lock()
	delete(c.staleBackend, key)
	c.mu.Unlock()
}

// backendStaleLocalValue returns the local value for key when the key is
// marked backend-stale, the mark is still within backendStaleMarkTTL, AND
// the local entry is still live. It reports found only in that case, so
// callers fall through to the normal backend-value path once the local
// entry expires OR the mark itself ages out — the latter is what lets a
// later cross-replica write eventually win for a value type
// backendValueIsNewer cannot compare (R4 cache review round 2). An
// expired mark is deleted here so it does not have to be re-evaluated (or
// pruned separately) on every subsequent Get for the same key.
func (c *UniversalCache) backendStaleLocalValue(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	markedAt, stale := c.staleBackend[key]
	if !stale {
		return nil, false
	}
	if time.Since(markedAt) > backendStaleMarkTTL {
		delete(c.staleBackend, key)
		return nil, false
	}
	item, exists := c.items[key]
	if !exists || time.Now().After(item.ExpiresAt) {
		return nil, false
	}
	return item.Value, true
}

// backendValueIsNewer reports whether backendValue is not older than
// localValue, for the narrow set of marker values a MonotonicMarkers cache
// actually stores: Unix timestamps (session invalidation) written as the
// native int64 locally and read back as float64 after a backend's JSON
// round-trip. It returns false whenever either value does not decode to a
// comparable number — including the blacklist cache's bool markers — so
// Get's backend-stale branch keeps its original FIX-04 behavior (always
// prefer local) for anything this comparison cannot make sense of.
//
// Callers MUST gate this on c.config.MonotonicMarkers (see Get) before
// trusting the result: for a cache that is not MonotonicMarkers, a larger
// number is not necessarily a newer write, so calling this at all (let
// alone trusting a "newer" result) risks the exact clobber FIX-04 exists to
// prevent (R4 cache review round 2, minor, universal_cache.go:546).
func backendValueIsNewer(backendValue, localValue interface{}) bool {
	backendNum, backendOK := comparableTimestamp(backendValue)
	localNum, localOK := comparableTimestamp(localValue)
	if !backendOK || !localOK {
		return false
	}
	return backendNum >= localNum
}

// comparableTimestamp converts a cache marker value into an int64 for
// backendValueIsNewer's comparison, regardless of which representation
// produced it (a native Go int64 from a local write, or a float64/
// json.Number from decoding backend JSON).
func comparableTimestamp(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	}
	return 0, false
}

// updateLocalCache updates the local cache with a value from the backend
func (c *UniversalCache) updateLocalCache(key string, value interface{}, ttl time.Duration) error {
	size := c.estimateSize(value)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict against NET growth for an existing key (the replace below frees the
	// old size), so the memory cap isn't over-triggered and live entries aren't
	// needlessly evicted. See setLocal.
	growth := size
	if existing, exists := c.items[key]; exists {
		growth = size - existing.Size
	}

	// Check memory limits
	if c.config.MaxMemoryBytes > 0 {
		for c.currentMemory+growth > c.config.MaxMemoryBytes && c.lruList.Len() > 0 {
			c.evictOldest()
		}
	}

	// Check size limits — only evict when inserting a NEW key. An in-place
	// update adds no net entry (the replace below frees the old size), so
	// evicting would drop an unrelated live LRU entry and leave the cache
	// one below capacity. See setLocal (R141).
	if _, present := c.items[key]; !present && c.lruList.Len() >= c.config.MaxSize {
		c.evictOldest()
	}

	now := time.Now()
	// Replace an existing entry in place: update the item and move its single
	// list node to the front. Without this, a repeat populate of the same key
	// (the per-request Get->backend-hit path) would PushFront a duplicate node
	// and overwrite c.items[key], orphaning the previous node. Orphans inflate
	// currentMemory/currentSize and, once eviction deletes the key, leave a
	// Back() node whose key is absent from c.items — so evictOldest() spins
	// while holding c.mu.Lock(): the 100%-CPU write-lock convoy seen in pprof.
	// setLocal dedups the same way; evictOldest also guards any dangling node.
	if existing, exists := c.items[key]; exists {
		c.currentMemory -= existing.Size
		c.lruList.Remove(existing.element)

		existing.Value = value
		existing.Size = size
		existing.ExpiresAt = now.Add(ttl)
		existing.LastAccessed = now
		existing.AccessCount++

		existing.element = c.lruList.PushFront(key)
		c.currentMemory += size

		return nil
	}

	item := &CacheItem{
		Key:          key,
		Value:        value,
		Size:         size,
		ExpiresAt:    now.Add(ttl),
		LastAccessed: now,
		AccessCount:  1,
		CacheType:    c.config.Type,
		Metadata:     make(map[string]interface{}),
	}

	item.element = c.lruList.PushFront(key)
	c.items[key] = item

	c.currentSize++
	c.currentMemory += size

	return nil
}
