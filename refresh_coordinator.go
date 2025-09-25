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
	// inFlightRefreshes tracks active refresh operations by refresh token hash
	inFlightRefreshes map[string]*refreshOperation
	// refreshMutex protects the inFlightRefreshes map
	refreshMutex sync.RWMutex

	// sessionRefreshAttempts tracks refresh attempts per session
	sessionRefreshAttempts map[string]*refreshAttemptTracker
	// attemptsMutex protects sessionRefreshAttempts map
	attemptsMutex sync.RWMutex

	// Circuit breaker for refresh operations
	circuitBreaker *RefreshCircuitBreaker

	// Configuration
	config RefreshCoordinatorConfig

	// Metrics
	metrics *RefreshMetrics

	// Logger
	logger *Logger

	// Cleanup goroutine control
	stopChan chan struct{}
	wg       sync.WaitGroup
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
	}
}

// refreshOperation represents an in-flight refresh operation
type refreshOperation struct {
	// refreshToken being refreshed (for validation)
	refreshToken string
	// result channel broadcasts the result to all waiting goroutines
	resultChan chan *refreshResult
	// startTime tracks when the operation started
	startTime time.Time
	// waiterCount tracks number of goroutines waiting
	waiterCount int32
}

// refreshResult contains the result of a refresh operation
type refreshResult struct {
	tokenResponse *TokenResponse
	err           error
	fromCache     bool
}

// refreshAttemptTracker tracks refresh attempts for a session
type refreshAttemptTracker struct {
	// attempts counts refresh attempts in current window
	attempts int32
	// lastAttemptTime is the timestamp of the last attempt
	lastAttemptTime time.Time
	// windowStartTime is when the current tracking window started
	windowStartTime time.Time
	// inCooldown indicates if this session is in cooldown
	inCooldown bool
	// cooldownEndTime is when cooldown period ends
	cooldownEndTime time.Time
	// consecutiveFailures tracks consecutive refresh failures
	consecutiveFailures int32
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

// RefreshCircuitBreaker implements a circuit breaker specifically for refresh operations
type RefreshCircuitBreaker struct {
	state           int32 // 0=closed, 1=open, 2=half-open
	failures        int32
	lastFailureTime time.Time
	lastSuccessTime time.Time
	config          RefreshCircuitBreakerConfig
	mutex           sync.RWMutex
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
	// Check circuit breaker first
	if !rc.circuitBreaker.AllowRequest() {
		atomic.AddInt64(&rc.metrics.circuitBreakerTrips, 1)
		return nil, fmt.Errorf("refresh circuit breaker is open due to repeated failures")
	}

	// Check session-level rate limiting
	if !rc.canAttemptRefresh(sessionID) {
		atomic.AddInt64(&rc.metrics.cooldownsTriggered, 1)
		return nil, fmt.Errorf("refresh attempts exceeded for session, in cooldown period")
	}

	// Check memory pressure
	if rc.config.EnableMemoryPressureDetection && rc.isUnderMemoryPressure() {
		atomic.AddInt64(&rc.metrics.memoryPressureEvents, 1)
		return nil, fmt.Errorf("system under memory pressure, refresh denied")
	}

	// Create hash of refresh token for deduplication
	tokenHash := rc.hashRefreshToken(refreshToken)

	// Try to join existing refresh operation
	if result := rc.joinExistingRefresh(ctx, tokenHash, refreshToken); result != nil {
		if result.fromCache {
			atomic.AddInt64(&rc.metrics.deduplicatedRequests, 1)
		}
		return result.tokenResponse, result.err
	}

	// Start new refresh operation
	return rc.executeRefresh(ctx, sessionID, tokenHash, refreshToken, refreshFunc)
}

// joinExistingRefresh attempts to join an in-flight refresh operation
func (rc *RefreshCoordinator) joinExistingRefresh(
	ctx context.Context,
	tokenHash string,
	refreshToken string,
) *refreshResult {
	rc.refreshMutex.RLock()
	operation, exists := rc.inFlightRefreshes[tokenHash]
	if exists && operation.refreshToken == refreshToken {
		// Increment waiter count
		atomic.AddInt32(&operation.waiterCount, 1)
		resultChan := operation.resultChan
		rc.refreshMutex.RUnlock()

		// Wait for result or context cancellation
		select {
		case result := <-resultChan:
			if result != nil {
				result.fromCache = true
			}
			return result
		case <-ctx.Done():
			return &refreshResult{nil, ctx.Err(), false}
		}
	}
	rc.refreshMutex.RUnlock()
	return nil
}

// executeRefresh performs a new refresh operation with deduplication
func (rc *RefreshCoordinator) executeRefresh(
	ctx context.Context,
	sessionID string,
	tokenHash string,
	refreshToken string,
	refreshFunc func() (*TokenResponse, error),
) (*TokenResponse, error) {
	// Check concurrent refresh limit
	currentInFlight := atomic.LoadInt32(&rc.metrics.currentInFlightRefreshes)
	if int(currentInFlight) >= rc.config.MaxConcurrentRefreshes {
		return nil, fmt.Errorf("maximum concurrent refresh operations reached")
	}

	// Create new operation
	operation := &refreshOperation{
		refreshToken: refreshToken,
		resultChan:   make(chan *refreshResult, 1),
		startTime:    time.Now(),
		waiterCount:  1,
	}

	// Register operation
	rc.refreshMutex.Lock()
	rc.inFlightRefreshes[tokenHash] = operation
	rc.refreshMutex.Unlock()

	atomic.AddInt32(&rc.metrics.currentInFlightRefreshes, 1)
	atomic.AddInt64(&rc.metrics.totalRefreshRequests, 1)

	// Track attempt
	rc.recordRefreshAttempt(sessionID)

	// Execute refresh with timeout
	go func() {
		defer func() {
			// Clean up operation
			rc.refreshMutex.Lock()
			delete(rc.inFlightRefreshes, tokenHash)
			rc.refreshMutex.Unlock()

			atomic.AddInt32(&rc.metrics.currentInFlightRefreshes, -1)
			close(operation.resultChan)
		}()

		// Create timeout context
		refreshCtx, cancel := context.WithTimeout(ctx, rc.config.RefreshTimeout)
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
			// Update circuit breaker
			if result.err != nil {
				rc.circuitBreaker.RecordFailure()
				rc.recordRefreshFailure(sessionID)
				atomic.AddInt64(&rc.metrics.failedRefreshes, 1)
			} else {
				rc.circuitBreaker.RecordSuccess()
				rc.recordRefreshSuccess(sessionID)
				atomic.AddInt64(&rc.metrics.successfulRefreshes, 1)
			}

			// Broadcast result to all waiters
			operation.resultChan <- &refreshResult{
				tokenResponse: result.resp,
				err:           result.err,
				fromCache:     false,
			}

		case <-refreshCtx.Done():
			// Timeout occurred
			err := fmt.Errorf("refresh operation timed out after %v", rc.config.RefreshTimeout)
			rc.circuitBreaker.RecordFailure()
			rc.recordRefreshFailure(sessionID)
			atomic.AddInt64(&rc.metrics.failedRefreshes, 1)

			operation.resultChan <- &refreshResult{
				tokenResponse: nil,
				err:           err,
				fromCache:     false,
			}
		}
	}()

	// Wait for result
	select {
	case result := <-operation.resultChan:
		return result.tokenResponse, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// canAttemptRefresh checks if a session can attempt refresh based on rate limiting
func (rc *RefreshCoordinator) canAttemptRefresh(sessionID string) bool {
	rc.attemptsMutex.Lock()
	defer rc.attemptsMutex.Unlock()

	tracker, exists := rc.sessionRefreshAttempts[sessionID]
	if !exists {
		// First attempt for this session
		rc.sessionRefreshAttempts[sessionID] = &refreshAttemptTracker{
			windowStartTime: time.Now(),
		}
		return true
	}

	now := time.Now()

	// Check if in cooldown
	if tracker.inCooldown {
		if now.After(tracker.cooldownEndTime) {
			// Cooldown expired, reset tracker
			tracker.inCooldown = false
			tracker.attempts = 0
			tracker.consecutiveFailures = 0
			tracker.windowStartTime = now
			return true
		}
		return false // Still in cooldown
	}

	// Check if window expired
	if now.Sub(tracker.windowStartTime) > rc.config.RefreshAttemptWindow {
		// Reset window
		tracker.attempts = 0
		tracker.windowStartTime = now
		return true
	}

	// Check attempt limit
	if int(tracker.attempts) >= rc.config.MaxRefreshAttempts {
		// Enter cooldown
		tracker.inCooldown = true
		tracker.cooldownEndTime = now.Add(rc.config.RefreshCooldownPeriod)
		rc.logger.Infof("Session %s entering refresh cooldown after %d attempts",
			sessionID, tracker.attempts)
		return false
	}

	return true
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
