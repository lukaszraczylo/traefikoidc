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
	inFlightRefreshes      map[string]*refreshOperation
	cleanupTimers          map[string]*time.Timer
	sessionRefreshAttempts map[string]*refreshAttemptTracker
	delayedCleanupQueue    chan delayedCleanupItem
	circuitBreaker         *RefreshCircuitBreaker
	metrics                *RefreshMetrics
	logger                 *Logger
	stopChan               chan struct{}
	config                 RefreshCoordinatorConfig
	wg                     sync.WaitGroup
	attemptsMutex          sync.RWMutex
	refreshMutex           sync.RWMutex
	cleanupTimerMu         sync.Mutex
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

// refreshAttemptTracker tracks refresh attempts for a session
type refreshAttemptTracker struct {
	lastAttemptTime     time.Time
	windowStartTime     time.Time
	cooldownEndTime     time.Time
	attempts            int32
	consecutiveFailures int32
	inCooldown          bool
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

// delayedCleanupItem represents an item scheduled for delayed cleanup
type delayedCleanupItem struct {
	cleanupAt time.Time
	tokenHash string
}

// RefreshCircuitBreaker implements a circuit breaker specifically for refresh operations
type RefreshCircuitBreaker struct {
	lastFailureTime time.Time
	lastSuccessTime time.Time
	config          RefreshCircuitBreakerConfig
	mutex           sync.RWMutex
	state           int32
	failures        int32
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
		inFlightRefreshes:      make(map[string]*refreshOperation),
		sessionRefreshAttempts: make(map[string]*refreshAttemptTracker),
		config:                 config,
		metrics:                &RefreshMetrics{},
		logger:                 logger,
		stopChan:               make(chan struct{}),
		delayedCleanupQueue:    make(chan delayedCleanupItem, 1000), // Buffered channel for cleanup items
		cleanupTimers:          make(map[string]*time.Timer),
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

	// Start delayed cleanup processor (single goroutine processes all cleanup timers)
	rc.wg.Add(1)
	go rc.processDelayedCleanups()

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
		// We created a new operation, so we need to execute it
		go rc.executeRefreshAsync(operation, sessionID, tokenHash, refreshFunc)
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
			// Record metrics based on result
			if result.err != nil {
				rc.circuitBreaker.RecordFailure()
				rc.recordRefreshFailure(sessionID)
				atomic.AddInt64(&rc.metrics.failedRefreshes, 1)
			} else {
				rc.circuitBreaker.RecordSuccess()
				rc.recordRefreshSuccess(sessionID)
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
	ctx context.Context,
	sessionID string,
	tokenHash string,
	refreshToken string,
) (*refreshOperation, bool, error) {
	rc.refreshMutex.Lock()
	defer rc.refreshMutex.Unlock()

	// Check for existing operation while holding the lock
	if existingOp, exists := rc.inFlightRefreshes[tokenHash]; exists {
		if existingOp.refreshToken == refreshToken {
			// Join existing operation
			atomic.AddInt32(&existingOp.waiterCount, 1)
			return existingOp, false, nil
		}
		// Different refresh token for same hash - should not happen
		return nil, false, fmt.Errorf("refresh token mismatch")
	}

	// No existing operation - check if we can create a new one
	// All checks happen while holding the lock to prevent races

	// Check and record refresh attempt for rate limiting
	rc.recordRefreshAttempt(sessionID)
	if rc.isInCooldown(sessionID) {
		atomic.AddInt64(&rc.metrics.cooldownsTriggered, 1)
		return nil, false, fmt.Errorf("refresh attempts exceeded for session, in cooldown period")
	}

	// Check memory pressure
	if rc.config.EnableMemoryPressureDetection && rc.isUnderMemoryPressure() {
		atomic.AddInt64(&rc.metrics.memoryPressureEvents, 1)
		return nil, false, fmt.Errorf("system under memory pressure, refresh denied")
	}

	// Check and reserve concurrent refresh slot atomically
	current := atomic.LoadInt32(&rc.metrics.currentInFlightRefreshes)
	if int(current) >= rc.config.MaxConcurrentRefreshes {
		return nil, false, fmt.Errorf("maximum concurrent refresh operations reached")
	}

	// Reserve the slot - we're still holding the lock so this is safe
	atomic.AddInt32(&rc.metrics.currentInFlightRefreshes, 1)

	// Create and register new operation
	operation := &refreshOperation{
		refreshToken: refreshToken,
		done:         make(chan struct{}),
		startTime:    time.Now(),
		waiterCount:  1,
	}
	rc.inFlightRefreshes[tokenHash] = operation

	return operation, true, nil
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
}

// scheduleDelayedCleanup schedules a cleanup using a timer instead of spawning a goroutine
// This prevents goroutine explosion under high load (500+ req/sec)
func (rc *RefreshCoordinator) scheduleDelayedCleanup(tokenHash string) {
	delay := rc.config.DeduplicationCleanupDelay
	if delay <= 0 {
		// Immediate cleanup
		rc.performCleanup(tokenHash)
		return
	}

	// Use time.AfterFunc which is more efficient than spawning a goroutine with Sleep
	// time.AfterFunc uses the runtime's timer heap which is much more efficient
	rc.cleanupTimerMu.Lock()
	// Cancel any existing timer for this hash (shouldn't happen, but just in case)
	if existingTimer, exists := rc.cleanupTimers[tokenHash]; exists {
		existingTimer.Stop()
	}
	rc.cleanupTimers[tokenHash] = time.AfterFunc(delay, func() {
		rc.performCleanup(tokenHash)
		// Remove timer from map
		rc.cleanupTimerMu.Lock()
		delete(rc.cleanupTimers, tokenHash)
		rc.cleanupTimerMu.Unlock()
	})
	rc.cleanupTimerMu.Unlock()
}

// performCleanup removes the operation from the in-flight map
func (rc *RefreshCoordinator) performCleanup(tokenHash string) {
	rc.refreshMutex.Lock()
	delete(rc.inFlightRefreshes, tokenHash)
	rc.refreshMutex.Unlock()
	atomic.AddInt32(&rc.metrics.currentInFlightRefreshes, -1)
}

// processDelayedCleanups processes delayed cleanup requests from the queue
// This is a single goroutine that handles all delayed cleanups
func (rc *RefreshCoordinator) processDelayedCleanups() {
	defer rc.wg.Done()

	for {
		select {
		case item := <-rc.delayedCleanupQueue:
			// Wait until cleanup time
			waitDuration := time.Until(item.cleanupAt)
			if waitDuration > 0 {
				select {
				case <-time.After(waitDuration):
				case <-rc.stopChan:
					return
				}
			}
			rc.performCleanup(item.tokenHash)
		case <-rc.stopChan:
			return
		}
	}
}

// isInCooldown checks if a session is in cooldown after recording an attempt
func (rc *RefreshCoordinator) isInCooldown(sessionID string) bool {
	rc.attemptsMutex.Lock()
	defer rc.attemptsMutex.Unlock()

	tracker, exists := rc.sessionRefreshAttempts[sessionID]
	if !exists {
		return false // No tracker means first attempt, not in cooldown
	}

	now := time.Now()

	// Check if already in cooldown
	if tracker.inCooldown {
		if now.After(tracker.cooldownEndTime) {
			// Cooldown expired, reset tracker
			tracker.inCooldown = false
			tracker.attempts = 1 // Already recorded one attempt
			tracker.consecutiveFailures = 0
			tracker.windowStartTime = now
			return false
		}
		return true // Still in cooldown
	}

	// Check if window expired
	if now.Sub(tracker.windowStartTime) > rc.config.RefreshAttemptWindow {
		// Reset window
		tracker.attempts = 1 // Already recorded one attempt
		tracker.windowStartTime = now
		return false
	}

	// Check if just exceeded attempt limit
	if int(tracker.attempts) >= rc.config.MaxRefreshAttempts {
		// Enter cooldown now
		tracker.inCooldown = true
		tracker.cooldownEndTime = now.Add(rc.config.RefreshCooldownPeriod)
		rc.logger.Infof("Session %s entering refresh cooldown after %d attempts",
			sessionID, tracker.attempts)
		return true
	}

	return false
}

// recordRefreshAttempt records a refresh attempt for rate limiting
func (rc *RefreshCoordinator) recordRefreshAttempt(sessionID string) {
	rc.attemptsMutex.Lock()
	defer rc.attemptsMutex.Unlock()

	tracker, exists := rc.sessionRefreshAttempts[sessionID]
	if !exists {
		tracker = &refreshAttemptTracker{
			windowStartTime: time.Now(),
		}
		rc.sessionRefreshAttempts[sessionID] = tracker
	}

	atomic.AddInt32(&tracker.attempts, 1)
	tracker.lastAttemptTime = time.Now()
}

// recordRefreshSuccess records a successful refresh
func (rc *RefreshCoordinator) recordRefreshSuccess(sessionID string) {
	rc.attemptsMutex.Lock()
	defer rc.attemptsMutex.Unlock()

	if tracker, exists := rc.sessionRefreshAttempts[sessionID]; exists {
		tracker.consecutiveFailures = 0
	}
}

// recordRefreshFailure records a failed refresh
func (rc *RefreshCoordinator) recordRefreshFailure(sessionID string) {
	rc.attemptsMutex.Lock()
	defer rc.attemptsMutex.Unlock()

	if tracker, exists := rc.sessionRefreshAttempts[sessionID]; exists {
		atomic.AddInt32(&tracker.consecutiveFailures, 1)
	}
}

// hashRefreshToken creates a hash of the refresh token for deduplication
func (rc *RefreshCoordinator) hashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// isUnderMemoryPressure checks if the system is under memory pressure
func (rc *RefreshCoordinator) isUnderMemoryPressure() bool {
	// This is a simplified check - in production you'd want to use runtime.MemStats
	// or system-specific memory monitoring
	return false // Placeholder - implement actual memory check
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

// cleanupStaleEntries removes outdated tracking entries
func (rc *RefreshCoordinator) cleanupStaleEntries() {
	now := time.Now()

	rc.attemptsMutex.Lock()
	defer rc.attemptsMutex.Unlock()

	// Clean up old session trackers
	for sessionID, tracker := range rc.sessionRefreshAttempts {
		// Remove trackers that haven't been used recently
		if now.Sub(tracker.lastAttemptTime) > 2*rc.config.RefreshAttemptWindow {
			delete(rc.sessionRefreshAttempts, sessionID)
		}
	}
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

// Shutdown gracefully shuts down the coordinator
func (rc *RefreshCoordinator) Shutdown() {
	close(rc.stopChan)

	// Cancel all pending cleanup timers
	rc.cleanupTimerMu.Lock()
	for _, timer := range rc.cleanupTimers {
		timer.Stop()
	}
	rc.cleanupTimers = make(map[string]*time.Timer)
	rc.cleanupTimerMu.Unlock()

	rc.wg.Wait()
}

// AllowRequest checks if the circuit breaker allows a request
func (cb *RefreshCircuitBreaker) AllowRequest() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	state := atomic.LoadInt32(&cb.state)

	switch state {
	case 0: // Closed
		return true
	case 1: // Open
		if time.Since(cb.lastFailureTime) > cb.config.OpenDuration {
			// Try to transition to half-open
			if atomic.CompareAndSwapInt32(&cb.state, 1, 2) {
				return true
			}
		}
		return false
	case 2: // Half-open
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful operation
func (cb *RefreshCircuitBreaker) RecordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	state := atomic.LoadInt32(&cb.state)
	if state == 2 { // Half-open
		// Close the circuit
		atomic.StoreInt32(&cb.state, 0)
		atomic.StoreInt32(&cb.failures, 0)
	} else if state == 0 { // Closed
		// Reset failure count on success
		atomic.StoreInt32(&cb.failures, 0)
	}
	cb.lastSuccessTime = time.Now()
}

// RecordFailure records a failed operation
func (cb *RefreshCircuitBreaker) RecordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	failures := atomic.AddInt32(&cb.failures, 1)
	cb.lastFailureTime = time.Now()

	state := atomic.LoadInt32(&cb.state)

	if state == 0 && int(failures) >= cb.config.MaxFailures {
		// Open the circuit
		atomic.StoreInt32(&cb.state, 1)
	} else if state == 2 {
		// Half-open failed, return to open
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
