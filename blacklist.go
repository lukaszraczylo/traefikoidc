package traefikoidc

import (
	"sync"
	"time"
)

// TokenBlacklist manages a thread-safe list of revoked tokens with expiration.
type TokenBlacklist struct {
	tokens map[string]time.Time
	mutex  sync.RWMutex
}

// NewTokenBlacklist creates a new token blacklist instance.
func NewTokenBlacklist() *TokenBlacklist {
	return &TokenBlacklist{
		tokens: make(map[string]time.Time),
	}
}

// Add adds a token to the blacklist with an expiration time.
func (b *TokenBlacklist) Add(token string, expiry time.Time) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Clean up expired tokens if we're at capacity
	if len(b.tokens) >= 1000 {
		now := time.Now()
		futureThreshold := now.Add(time.Minute)
		for t, exp := range b.tokens {
			if now.After(exp) || futureThreshold.After(exp) {
				delete(b.tokens, t)
			}
		}

		// If still at capacity, remove oldest token
		if len(b.tokens) >= 1000 {
			var oldestToken string
			var oldestTime time.Time
			first := true
			for t, exp := range b.tokens {
				if first || exp.Before(oldestTime) {
					oldestToken = t
					oldestTime = exp
					first = false
				}
			}
			if oldestToken != "" {
				delete(b.tokens, oldestToken)
			}
		}
	}

	b.tokens[token] = expiry
}

// IsBlacklisted checks if a token is in the blacklist and not expired.
func (b *TokenBlacklist) IsBlacklisted(token string) bool {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	expiry, exists := b.tokens[token]
	if !exists {
		return false
	}

	// If token is expired, remove it and return false
	if time.Now().After(expiry) {
		// Switch to write lock to remove expired token
		b.mutex.RUnlock()
		b.mutex.Lock()
		delete(b.tokens, token)
		b.mutex.Unlock()
		b.mutex.RLock()
		return false
	}

	return true
}

// Cleanup removes expired tokens from the blacklist.
// Also removes tokens that will expire within the next minute to prevent edge cases.
func (b *TokenBlacklist) Cleanup() {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	now := time.Now()
	futureThreshold := now.Add(time.Minute)

	for token, expiry := range b.tokens {
		// Remove tokens that are expired or will expire soon
		if now.After(expiry) || futureThreshold.After(expiry) {
			delete(b.tokens, token)
		}
	}
}

// Remove removes a token from the blacklist regardless of its expiration.
func (b *TokenBlacklist) Remove(token string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	delete(b.tokens, token)
}

// Count returns the current number of tokens in the blacklist.
func (b *TokenBlacklist) Count() int {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	return len(b.tokens)
}
