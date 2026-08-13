package traefikoidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// RefreshCoordinator prevents duplicate refresh token operations and manages
// refresh attempt tracking to prevent infinite loops and OOM conditions.
// It implements request coalescing, rate limiting, and circuit breaking
// specifically for token refresh operations.
type RefreshCoordinator struct {
	// inFlightRefreshes maps tokenHash -> *refreshOperation. sync.Map is used
	// instead of a plain map + RWMutex so concurrent refreshes do not
	// serialize on a single global lock. Under Yaegi the previous
	// refreshMutex.Lock() was held for tens of milliseconds per request due
	// to interpreter overhead on the work inside the critical section,
	// causing dozens of goroutines to stack up on it and pin one CPU core.
	inFlightRefreshes sync.Map
	// sessionRefreshAttempts maps sessionID -> *refreshAttemptTracker.
	// sync.Map + atomic tracker fields means isInCooldown/recordRefreshAttempt/
	// recordRefreshSuccess/recordRefreshFailure are lock-free. Previously
	// these used attemptsMutex sync.RWMutex; under Yaegi every Lock() acquisition
	// adds 10-50ms of dispatch overhead, and they were called twice per leader
	// request (once for recordRefreshAttempt, once for isInCooldown). That
	// serializing pattern caused the v1.0.15 death spiral after v1.0.14
	// removed the refreshMutex (same architectural shape, different mutex).
	sessionRefreshAttempts sync.Map
	circuitBreaker         *RefreshCircuitBreaker
	metrics                *RefreshMetrics
	logger                 *Logger
	stopChan               chan struct{}
	config                 RefreshCoordinatorConfig
	wg                     sync.WaitGroup
	// shutdownOnce makes Shutdown idempotent: close(rc.stopChan) on an
	// already-closed channel would panic ('close of closed channel').
	// Repeated setup/teardown (e.g. Traefik plugin reload) can close the
	// same Authenticator -> same coordinator more than once.
	shutdownOnce sync.Once
}

// RefreshCoordinatorConfig configures the refresh coordinator behavior
type RefreshCoordinatorConfig struct {
	// Maximum refresh attempts per session before giving up
	MaxRefreshAttempts int
	// Time window for refresh attempt tracking
	RefreshAttemptWindow time.Duration
	// Cooldown period after max attempts reached
	RefreshCooldownPeriod time.Duration
	// Maximum concurrent refresh operations
	MaxConcurrentRefreshes int
	// Timeout for individual refresh operations
	RefreshTimeout time.Duration
	// Enable memory pressure detection
	EnableMemoryPressureDetection bool
	// Memory pressure threshold (in MB)
	MemoryPressureThresholdMB uint64
	// Cleanup interval for stale entries
	CleanupInterval time.Duration
	// Delay before cleaning up completed refresh operations from deduplication map
	// Set to 0 for immediate cleanup (useful for tests)
	DeduplicationCleanupDelay time.Duration
}

// DefaultRefreshCoordinatorConfig returns production-ready configuration
func DefaultRefreshCoordinatorConfig() RefreshCoordinatorConfig {
	return RefreshCoordinatorConfig{
		MaxRefreshAttempts:            5,
		RefreshAttemptWindow:          5 * time.Minute,
		RefreshCooldownPeriod:         10 * time.Minute,
		MaxConcurrentRefreshes:        10,
		RefreshTimeout:                30 * time.Second,
		EnableMemoryPressureDetection: true,
		MemoryPressureThresholdMB:     500, // 500MB threshold
		CleanupInterval:               1 * time.Minute,
		DeduplicationCleanupDelay:     100 * time.Millisecond, // Default 100ms for production
	}
}

// refreshOperation represents an in-flight refresh operation
type refreshOperation struct {
	startTime    time.Time
	result       *refreshResult
	done         chan struct{}
	refreshToken string
	mutex        sync.RWMutex
	waiterCount  int32
}

// refreshResult contains the result of a refresh operation
type refreshResult struct {
	tokenResponse *TokenResponse
	err           error
	fromCache     bool
}

// attemptState is the immutable snapshot of a session's refresh-attempt
// state. Lives behind refreshAttemptTracker.state (atomic.Value). Every
// transition (record, success, failure, window-reset, cooldown-enter,
// cooldown-exit) constructs a fresh attemptState and publishes it via
// CompareAndSwap so the entire field set is updated together.
//
// Per-field atomic.Load/Store (the previous v1.0.15 design) had a benign
// but observable hazard: the cooldown-exit reset wrote cooldownEndNano = 0
// first, then separately stored attempts = 1 and windowStartNano = now.
// A concurrent isInCooldown call could see cooldownEndNano = 0 (reset
// just completed) with attempts still at MaxRefreshAttempts, triggering
// a fresh cooldown immediately. The snapshot approach eliminates the
// intermediate state entirely.
type attemptState struct {
	lastAttemptNano     int64 // UnixNano of last attempt
	windowStartNano     int64 // UnixNano of attempt-window start
	cooldownEndNano     int64 // UnixNano; 0 = not in cooldown
	attempts            int32
	consecutiveFailures int32
}

// refreshAttemptTracker tracks refresh attempts for a session via a single
// atomic.Value holding a *attemptState pointer. Readers do exactly one Load.
// Writers do Load → construct new → CompareAndSwap (retry on conflict).
// Under Yaegi this collapses 3-4 per-field atomic dispatches into one Load,
// and eliminates the cross-field race in the window-reset path.
type refreshAttemptTracker struct {
	state atomic.Value // *attemptState
}

// stateOf returns the current attemptState, or a zero-value snapshot if none
// has been published yet. The empty snapshot represents "no attempts recorded".
func (t *refreshAttemptTracker) stateOf() *attemptState {
	if v := t.state.Load(); v != nil {
		s, _ := v.(*attemptState)
		if s != nil {
			return s
		}
	}
	return &attemptState{}
}

// RefreshMetrics tracks coordinator performance metrics
type RefreshMetrics struct {
	totalRefreshRequests     int64
	deduplicatedRequests     int64
	successfulRefreshes      int64
	failedRefreshes          int64
	circuitBreakerTrips      int64
	memoryPressureEvents     int64
	cooldownsTriggered       int64
	currentInFlightRefreshes int32
}

// RefreshCircuitBreaker implements a circuit breaker specifically for refresh
// operations. All mutable fields are atomic so AllowRequest/RecordSuccess/
// RecordFailure run without any mutex. The previous sync.RWMutex.RLock() was
// taken on every CoordinateRefresh — under Yaegi this added 10-50ms of
// interpreter dispatch per call, which compounded with attemptsMutex to keep
// the pod's single CPU core saturated.
type RefreshCircuitBreaker struct {
	lastFailureNano int64 // atomic, UnixNano of most recent failure
	lastSuccessNano int64 // atomic, UnixNano of most recent success
	config          RefreshCircuitBreakerConfig
	state           int32 // atomic: 0=closed, 1=open, 2=half-open
	failures        int32 // atomic
}

// RefreshCircuitBreakerConfig configures the refresh circuit breaker
type RefreshCircuitBreakerConfig struct {
	MaxFailures      int
	OpenDuration     time.Duration
	HalfOpenRequests int
}

// NewRefreshCoordinator creates a new refresh coordinator
func NewRefreshCoordinator(config RefreshCoordinatorConfig, logger *Logger) *RefreshCoordinator {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
	}

	rc := &RefreshCoordinator{
		// inFlightRefreshes and sessionRefreshAttempts are both sync.Map;
		// their zero values are ready to use.
		config:        config,
		metrics:  &RefreshMetrics{},
		logger:   logger,
		stopChan: make(chan struct{}),
		circuitBreaker: &RefreshCircuitBreaker{
			config: RefreshCircuitBreakerConfig{
				MaxFailures:      3,
				OpenDuration:     30 * time.Second,
				HalfOpenRequests: 1,
			},
		},
	}

	// Start cleanup goroutine
	rc.wg.Add(1)
	go rc.cleanupRoutine()

	return rc
}

// CoordinateRefresh ensures only one refresh operation happens per refresh token
// and implements request coalescing for concurrent refresh attempts
func (rc *RefreshCoordinator) CoordinateRefresh(
	ctx context.Context,
	sessionID string,
	refreshToken string,
	refreshFunc func() (*TokenResponse, error),
) (*TokenResponse, error) {
	// Increment total request count
	atomic.AddInt64(&rc.metrics.totalRefreshRequests, 1)

	// Check circuit breaker first
	if !rc.circuitBreaker.AllowRequest() {
		atomic.AddInt64(&rc.metrics.circuitBreakerTrips, 1)
		return nil, fmt.Errorf("refresh circuit breaker is open due to repeated failures")
	}

	// Create hash of refresh token for deduplication
	tokenHash := rc.hashRefreshToken(refreshToken)

	// CRITICAL FIX: Atomically check for existing operation OR create new one
	// This prevents the race where multiple goroutines check, find nothing, then all create
	operation, isNew, err := rc.getOrCreateOperation(ctx, sessionID, tokenHash, refreshToken)

	if err != nil {
		// Operation creation was rejected (rate limit, memory pressure, concurrent limit)
		return nil, err
	}

	if isNew {
		// We created a new operation, so we need to execute it. Track the
		// goroutine so Shutdown waits for in-flight refreshes to finish (they
		// are aborted promptly via rc.ctx when stopChan closes).
		rc.wg.Add(1)
		go func() {
			defer rc.wg.Done()
			rc.executeRefreshAsync(operation, sessionID, tokenHash, refreshFunc) //nolint:gosec // long-lived background refresh intentionally uses a background context
		}()
	} else {
		// Joined existing operation - this is a deduplicated request
		atomic.AddInt64(&rc.metrics.deduplicatedRequests, 1)
	}

	// Wait for the operation to complete
	select {
	case <-operation.done:
		// Get the result
		operation.mutex.RLock()
		result := operation.result
		operation.mutex.RUnlock()

		if result != nil {
			// Per-request counters only. The circuit breaker and per-session
			// success/failure trackers must be recorded exactly once per
			// refresh OPERATION (in executeRefreshAsync), not once per waiter:
			// N requests coalescing onto a single refresh would otherwise
			// multiply one upstream result into N failure records and
			// over-trigger the circuit breaker (MaxFailures=3).
			if result.err != nil {
				atomic.AddInt64(&rc.metrics.failedRefreshes, 1)
			} else {
				atomic.AddInt64(&rc.metrics.successfulRefreshes, 1)
			}
			return result.tokenResponse, result.err
		}
		return nil, fmt.Errorf("refresh operation completed without result")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// getOrCreateOperation atomically checks for an existing operation or creates a new one
// Returns (operation, true, nil) if a new operation was created
// Returns (operation, false, nil) if joined an existing operation
// Returns (nil, false, error) if the operation was rejected
func (rc *RefreshCoordinator) getOrCreateOperation(
	_ context.Context,
	sessionID string,
	tokenHash string,
	refreshToken string,
) (*refreshOperation, bool, error) {
	// Speculatively construct the operation we WOULD register if we win the
	// race. Allocating here keeps the LoadOrStore call below atomic and
	// avoids any global lock — under Yaegi the previous map+RWMutex design
	// held the write lock long enough (tens of ms per call) that concurrent
	// refreshes on the same coordinator serialized into a queue that grew
	// without bound. See struct comment on inFlightRefreshes.
	candidate := &refreshOperation{
		refreshToken: refreshToken,
		done:         make(chan struct{}),
		startTime:    time.Now(),
		waiterCount:  1,
	}

	if existing, loaded := rc.inFlightRefreshes.LoadOrStore(tokenHash, candidate); loaded {
		existingOp, ok := existing.(*refreshOperation)
		if !ok {
			// Defensive: anything stored here is always *refreshOperation, but
			// keep the typed assert so a programming error elsewhere doesn't
			// surface as a confusing panic in an interpreter frame.
			return nil, false, fmt.Errorf("inFlightRefreshes corrupt: unexpected type %T", existing)
		}
		if existingOp.refreshToken == refreshToken {
			atomic.AddInt32(&existingOp.waiterCount, 1)
			return existingOp, false, nil
		}
		// Different refresh token for same hash - should not happen
		return nil, false, fmt.Errorf("refresh token mismatch")
	}

	// We won the race and registered `candidate`. Apply gates now. If any
	// gate fails we must remove our entry from the map and signal failure
	// to any joiners that snuck in between LoadOrStore and now.
	if err := rc.applyLeaderGates(sessionID); err != nil {
		rc.failCandidate(tokenHash, candidate, err)
		return nil, false, err
	}

	// Reserve concurrent slot via ticket-and-return: increment optimistically,
	// decrement if we overshot the limit. The previous CAS-loop allowed a
	// transient overshoot of up to N-1 leaders when several goroutines all
	// observed `current < max` in the same scheduling slice before any one
	// of them succeeded their CAS — visible to readers as
	// currentInFlightRefreshes > MaxConcurrentRefreshes for a brief window.
	// The ticket pattern is strictly bounded: the counter momentarily reads
	// max+k for k concurrent attempts past the limit, but only the k that
	// produced max+1..max+k decrement back, and only k=1 ever observes max+1
	// as committed.
	newCount := atomic.AddInt32(&rc.metrics.currentInFlightRefreshes, 1)
	if int(newCount) > rc.config.MaxConcurrentRefreshes {
		atomic.AddInt32(&rc.metrics.currentInFlightRefreshes, -1)
		err := fmt.Errorf("maximum concurrent refresh operations reached")
		rc.failCandidate(tokenHash, candidate, err)
		return nil, false, err
	}

	return candidate, true, nil
}

// applyLeaderGates runs the rate-limit, cooldown, and memory-pressure checks
// that previously ran under the global refreshMutex. Only the leader (the
// goroutine that just registered the operation) runs them; joiners share the
// leader's outcome via operation.done.
func (rc *RefreshCoordinator) applyLeaderGates(sessionID string) error {
	// Cooldown check FIRST, BEFORE incrementing the attempt counter.
	// Previously this function recorded the attempt and then read the
	// cooldown state. Under burst load (many concurrent leaders with
	// different token hashes but same session) every goroutine could
	// increment past MaxRefreshAttempts before any one of them observed
	// the threshold, so the cooldown gate fired too late — the same
	// thundering-herd shape that drove v1.0.14 into the ground.
	if rc.isInCooldown(sessionID) {
		atomic.AddInt64(&rc.metrics.cooldownsTriggered, 1)
		return fmt.Errorf("refresh attempts exceeded for session, in cooldown period")
	}
	if rc.config.EnableMemoryPressureDetection && rc.isUnderMemoryPressure() {
		atomic.AddInt64(&rc.metrics.memoryPressureEvents, 1)
		return fmt.Errorf("system under memory pressure, refresh denied")
	}
	// Only count attempts that actually progress past the gates.
	rc.recordRefreshAttempt(sessionID)
	return nil
}

// failCandidate removes the leader's just-registered operation from the
// in-flight map and signals the error to any joiners by recording the result
// and closing the done channel. This keeps the (nil, false, err) return path
// equivalent to the pre-sync.Map version: callers see the error directly,
// joiners see it via operation.done.
func (rc *RefreshCoordinator) failCandidate(tokenHash string, op *refreshOperation, err error) {
	rc.inFlightRefreshes.Delete(tokenHash)
	op.mutex.Lock()
	op.result = &refreshResult{err: err}
	op.mutex.Unlock()
	close(op.done)
}

// executeRefreshAsync performs the actual refresh operation asynchronously
func (rc *RefreshCoordinator) executeRefreshAsync(
	operation *refreshOperation,
	sessionID string,
	tokenHash string,
	refreshFunc func() (*TokenResponse, error),
) {
	defer func() {
		// Signal completion to all waiters
		close(operation.done)

		// Schedule delayed cleanup using timer instead of spawning a goroutine
		// This prevents goroutine explosion under high load
		rc.scheduleDelayedCleanup(tokenHash)
	}()

	// Create timeout context
	refreshCtx, cancel := context.WithTimeout(context.Background(), rc.config.RefreshTimeout)
	defer cancel()

	// Execute refresh in goroutine to respect timeout
	resultChan := make(chan struct {
		resp *TokenResponse
		err  error
	}, 1)

	go func() {
		resp, err := refreshFunc()
		select {
		case resultChan <- struct {
			resp *TokenResponse
			err  error
		}{resp, err}:
		case <-refreshCtx.Done():
		}
	}()

	select {
	case result := <-resultChan:
		// Store result for all waiters
		operation.mutex.Lock()
		operation.result = &refreshResult{
			tokenResponse: result.resp,
			err:           result.err,
			fromCache:     false,
		}
		operation.mutex.Unlock()
	case <-refreshCtx.Done():
		// Timeout occurred
		timeoutErr := fmt.Errorf("refresh operation timed out after %v", rc.config.RefreshTimeout)
		operation.mutex.Lock()
		operation.result = &refreshResult{
			tokenResponse: nil,
			err:           timeoutErr,
			fromCache:     false,
		}
		operation.mutex.Unlock()
	}

	// Record the circuit breaker and per-session outcome exactly once per
	// refresh operation. This function runs once per operation regardless of
	// how many requests coalesced onto it (see CoordinateRefresh), so a
	// single upstream refresh yields a single CB/session record rather than
	// N (one per waiter), which would over-trigger the circuit breaker.
	if err := operation.result.err; err != nil {
		rc.circuitBreaker.RecordFailure()
		rc.recordRefreshFailure(sessionID)
	} else {
		rc.circuitBreaker.RecordSuccess()
		rc.recordRefreshSuccess(sessionID)
	}
}

// scheduleDelayedCleanup schedules a cleanup using a timer instead of spawning
// a goroutine — time.AfterFunc uses the runtime's timer heap and never spawns
// a per-timer goroutine until the callback actually fires.
//
// The previous implementation tracked every pending timer in a map guarded by
// cleanupTimerMu so a duplicate scheduling could cancel the prior timer. That
// "shouldn't happen" path was the only consumer of the map, but the mutex
// fired on every successful refresh completion — yet another per-request
// Yaegi-dispatched lock acquisition. performCleanup is already idempotent
// (LoadAndDelete on the sync.Map), so a duplicate scheduling at worst fires
// performCleanup twice; the second call is a no-op. Dropping the map removes
// the whole class of contention on this code path.
func (rc *RefreshCoordinator) scheduleDelayedCleanup(tokenHash string) {
	delay := rc.config.DeduplicationCleanupDelay
	if delay <= 0 {
		rc.performCleanup(tokenHash)
		return
	}
	time.AfterFunc(delay, func() { rc.performCleanup(tokenHash) })
}

// performCleanup removes the operation from the in-flight map.
// Idempotent: only decrements the in-flight counter if an entry was actually
// removed. LoadAndDelete is atomic so any concurrent failCandidate or repeat
// cleanup call will see exactly one removal — the budget cannot be corrupted
// by double-decrement.
func (rc *RefreshCoordinator) performCleanup(tokenHash string) {
	if _, existed := rc.inFlightRefreshes.LoadAndDelete(tokenHash); existed {
		atomic.AddInt32(&rc.metrics.currentInFlightRefreshes, -1)
	}
}

// getOrCreateTracker fetches the tracker for sessionID or atomically creates a
// fresh one. The sync.Map.LoadOrStore semantics make this lock-free even under
// concurrent first-touch races: at most one tracker per sessionID survives.
//
// trackerFromMapValue centralizes the type assertion so the lint-mandated
// two-value form lives in one place; the stored type is always
// *refreshAttemptTracker by construction.
func trackerFromMapValue(v interface{}) *refreshAttemptTracker {
	t, _ := v.(*refreshAttemptTracker)
	return t
}

func (rc *RefreshCoordinator) getOrCreateTracker(sessionID string) *refreshAttemptTracker {
	if v, ok := rc.sessionRefreshAttempts.Load(sessionID); ok {
		return trackerFromMapValue(v)
	}
	fresh := &refreshAttemptTracker{}
	fresh.state.Store(&attemptState{windowStartNano: time.Now().UnixNano()})
	actual, _ := rc.sessionRefreshAttempts.LoadOrStore(sessionID, fresh)
	return trackerFromMapValue(actual)
}

// mutateState performs a CompareAndSwap loop that applies mutate to the
// current snapshot. mutate must be PURE: it receives an immutable view of
// the current state and returns a fresh *attemptState. If mutate returns nil
// the update is skipped (used by isInCooldown for "no change needed" paths).
//
// Retries on CAS conflict are bounded by the number of concurrent writers —
// in practice 1-3. Under Yaegi each retry pays the dispatch cost of one Load
// + one CompareAndSwap; still cheaper than the previous per-field atomic
// sequence and immune to the cross-field race the v1.0.15 design had.
func (t *refreshAttemptTracker) mutateState(mutate func(cur *attemptState) *attemptState) *attemptState {
	for {
		cur := t.stateOf()
		next := mutate(cur)
		if next == nil {
			return cur
		}
		if t.state.CompareAndSwap(cur, next) {
			return next
		}
	}
}

// isInCooldown checks if a session is in cooldown. Snapshot-based: every
// transition publishes a fresh *attemptState atomically so readers never see
// a partially-updated state. The previous per-field atomic design had a
// benign race in the cooldown-exit path (cooldownEndNano reset before
// attempts reset) that could double-trigger cooldown.
func (rc *RefreshCoordinator) isInCooldown(sessionID string) bool {
	v, ok := rc.sessionRefreshAttempts.Load(sessionID)
	if !ok {
		return false // No tracker means first attempt, not in cooldown
	}
	tracker := trackerFromMapValue(v)
	now := time.Now()
	nowNano := now.UnixNano()
	maxAttempts := rc.config.MaxRefreshAttempts
	window := rc.config.RefreshAttemptWindow
	cooldownPeriod := rc.config.RefreshCooldownPeriod

	cur := tracker.stateOf()

	// Already in cooldown?
	if cur.cooldownEndNano != 0 {
		if nowNano <= cur.cooldownEndNano {
			return true // still in cooldown
		}
		// Cooldown expired: atomically publish a fresh state with the window
		// restarted from one attempt. Whichever goroutine wins the CAS sets
		// the new snapshot; losers see it via the next stateOf load.
		tracker.mutateState(func(s *attemptState) *attemptState {
			if s.cooldownEndNano == 0 || nowNano <= s.cooldownEndNano {
				return nil // someone else already reset, or back in cooldown
			}
			return &attemptState{
				windowStartNano: nowNano,
				attempts:        1,
			}
		})
		return false
	}

	// Window expired?
	if time.Duration(nowNano-cur.windowStartNano) > window {
		tracker.mutateState(func(s *attemptState) *attemptState {
			if time.Duration(nowNano-s.windowStartNano) <= window {
				return nil
			}
			next := *s
			next.windowStartNano = nowNano
			next.attempts = 1
			return &next
		})
		return false
	}

	// Just exceeded attempt limit?
	if int(cur.attempts) >= maxAttempts {
		end := now.Add(cooldownPeriod).UnixNano()
		published := tracker.mutateState(func(s *attemptState) *attemptState {
			if s.cooldownEndNano != 0 {
				return nil
			}
			next := *s
			next.cooldownEndNano = end
			return &next
		})
		if published.cooldownEndNano == end {
			rc.logger.Infof("Session %s entering refresh cooldown after %d attempts",
				sessionID, published.attempts)
		}
		return true
	}

	return false
}

// recordRefreshAttempt records a refresh attempt for rate limiting. Lock-free
// snapshot mutation; attempts and lastAttemptNano are advanced atomically.
func (rc *RefreshCoordinator) recordRefreshAttempt(sessionID string) {
	tracker := rc.getOrCreateTracker(sessionID)
	nowNano := time.Now().UnixNano()
	tracker.mutateState(func(s *attemptState) *attemptState {
		next := *s
		next.attempts++
		next.lastAttemptNano = nowNano
		return &next
	})
}

// recordRefreshSuccess records a successful refresh: zero consecutiveFailures.
func (rc *RefreshCoordinator) recordRefreshSuccess(sessionID string) {
	v, ok := rc.sessionRefreshAttempts.Load(sessionID)
	if !ok {
		return
	}
	trackerFromMapValue(v).mutateState(func(s *attemptState) *attemptState {
		if s.consecutiveFailures == 0 {
			return nil
		}
		next := *s
		next.consecutiveFailures = 0
		return &next
	})
}

// recordRefreshFailure records a failed refresh: increments consecutiveFailures.
func (rc *RefreshCoordinator) recordRefreshFailure(sessionID string) {
	v, ok := rc.sessionRefreshAttempts.Load(sessionID)
	if !ok {
		return
	}
	trackerFromMapValue(v).mutateState(func(s *attemptState) *attemptState {
		next := *s
		next.consecutiveFailures++
		return &next
	})
}

// hashRefreshToken creates a hash of the refresh token for deduplication
func (rc *RefreshCoordinator) hashRefreshToken(token string) string {
	return refreshCoordinatorSessionID(token)
}

// refreshCoordinatorSessionID derives a stable identifier from a refresh token
// for both deduplication and per-session attempt tracking. Using sha256 of the
// raw token means each rotation produces a fresh sessionID with its own attempt
// budget, which is what we want.
func refreshCoordinatorSessionID(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// refreshCoordinatorWaitTimeout caps how long a request may wait for a
// coordinated refresh result. It is wider than RefreshTimeout so a follower
// always sees the leader's result instead of timing out independently.
const refreshCoordinatorWaitTimeout = 35 * time.Second

// isUnderMemoryPressure checks if the system is under memory pressure by
// consulting the global memory monitor. Returns true when pressure reaches
// High or Critical, at which point we refuse new refresh operations to
// avoid aggravating an already-stressed heap.
func (rc *RefreshCoordinator) isUnderMemoryPressure() bool {
	monitor := GetGlobalMemoryMonitor()
	if monitor == nil {
		return false
	}
	return monitor.GetMemoryPressure() >= MemoryPressureHigh
}

// cleanupRoutine periodically cleans up stale tracking entries
func (rc *RefreshCoordinator) cleanupRoutine() {
	defer rc.wg.Done()

	ticker := time.NewTicker(rc.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rc.cleanupStaleEntries()
		case <-rc.stopChan:
			return
		}
	}
}

// cleanupStaleEntries removes outdated tracking entries. Lock-free iteration
// via sync.Map.Range; safe to race with concurrent reads/writes.
func (rc *RefreshCoordinator) cleanupStaleEntries() {
	cutoff := time.Now().Add(-2 * rc.config.RefreshAttemptWindow).UnixNano()
	rc.sessionRefreshAttempts.Range(func(key, value interface{}) bool {
		tracker := trackerFromMapValue(value)
		if tracker == nil {
			return true
		}
		if tracker.stateOf().lastAttemptNano < cutoff {
			// Compare-and-delete to avoid evicting a tracker that was just
			// re-used by a concurrent caller. We compare by pointer identity.
			rc.sessionRefreshAttempts.CompareAndDelete(key, value)
		}
		return true
	})
}

// GetMetrics returns current coordinator metrics
func (rc *RefreshCoordinator) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"total_requests":         atomic.LoadInt64(&rc.metrics.totalRefreshRequests),
		"deduplicated_requests":  atomic.LoadInt64(&rc.metrics.deduplicatedRequests),
		"successful_refreshes":   atomic.LoadInt64(&rc.metrics.successfulRefreshes),
		"failed_refreshes":       atomic.LoadInt64(&rc.metrics.failedRefreshes),
		"circuit_breaker_trips":  atomic.LoadInt64(&rc.metrics.circuitBreakerTrips),
		"memory_pressure_events": atomic.LoadInt64(&rc.metrics.memoryPressureEvents),
		"cooldowns_triggered":    atomic.LoadInt64(&rc.metrics.cooldownsTriggered),
		"current_inflight":       atomic.LoadInt32(&rc.metrics.currentInFlightRefreshes),
		"circuit_breaker_state":  rc.circuitBreaker.GetState(),
	}
}

// Shutdown gracefully shuts down the coordinator. Pending delayed-cleanup
// timers are NOT canceled explicitly: time.AfterFunc callbacks are tiny
// (one map LoadAndDelete) and harmless after Shutdown — sync.Map operations
// remain safe on an unused coordinator until GC.
func (rc *RefreshCoordinator) Shutdown() {
	rc.shutdownOnce.Do(func() {
		close(rc.stopChan)
		rc.wg.Wait()
	})
}

// AllowRequest reports whether the circuit breaker allows a request. Lock-free.
func (cb *RefreshCircuitBreaker) AllowRequest() bool {
	switch atomic.LoadInt32(&cb.state) {
	case 0: // closed
		return true
	case 1: // open
		lastFail := atomic.LoadInt64(&cb.lastFailureNano)
		if time.Duration(time.Now().UnixNano()-lastFail) > cb.config.OpenDuration {
			// Transition to half-open; first CAS winner gets the probe.
			if atomic.CompareAndSwapInt32(&cb.state, 1, 2) {
				return true
			}
		}
		return false
	case 2: // half-open
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful operation. Lock-free.
func (cb *RefreshCircuitBreaker) RecordSuccess() {
	switch atomic.LoadInt32(&cb.state) {
	case 2: // half-open -> close
		atomic.StoreInt32(&cb.state, 0)
		atomic.StoreInt32(&cb.failures, 0)
	case 0: // closed
		atomic.StoreInt32(&cb.failures, 0)
	}
	atomic.StoreInt64(&cb.lastSuccessNano, time.Now().UnixNano())
}

// RecordFailure records a failed operation. Lock-free.
func (cb *RefreshCircuitBreaker) RecordFailure() {
	failures := atomic.AddInt32(&cb.failures, 1)
	atomic.StoreInt64(&cb.lastFailureNano, time.Now().UnixNano())

	switch atomic.LoadInt32(&cb.state) {
	case 0:
		if int(failures) >= cb.config.MaxFailures {
			atomic.StoreInt32(&cb.state, 1)
		}
	case 2:
		// Half-open probe failed -> back to open.
		atomic.StoreInt32(&cb.state, 1)
	}
}

// GetState returns the current state of the circuit breaker
func (cb *RefreshCircuitBreaker) GetState() string {
	state := atomic.LoadInt32(&cb.state)
	switch state {
	case 0:
		return "closed"
	case 1:
		return "open"
	case 2:
		return "half-open"
	default:
		return "unknown"
	}
}
