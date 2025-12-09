package mocks

import (
	"time"

	"github.com/stretchr/testify/mock"
)

// Cache is a testify mock for cache operations
type Cache struct {
	mock.Mock
}

// Get retrieves a value from the cache
func (m *Cache) Get(key string) (interface{}, bool) {
	args := m.Called(key)
	return args.Get(0), args.Bool(1)
}

// Set stores a value in the cache
func (m *Cache) Set(key string, value interface{}) {
	m.Called(key, value)
}

// SetWithTTL stores a value with a specific TTL
func (m *Cache) SetWithTTL(key string, value interface{}, ttl time.Duration) {
	m.Called(key, value, ttl)
}

// Delete removes a value from the cache
func (m *Cache) Delete(key string) {
	m.Called(key)
}

// Has checks if a key exists in the cache
func (m *Cache) Has(key string) bool {
	args := m.Called(key)
	return args.Bool(0)
}

// Clear removes all entries from the cache
func (m *Cache) Clear() {
	m.Called()
}

// Close closes the cache
func (m *Cache) Close() {
	m.Called()
}

// Size returns the number of items in the cache
func (m *Cache) Size() int {
	args := m.Called()
	return args.Int(0)
}

// TokenCache is a testify mock for token-specific cache operations
type TokenCache struct {
	mock.Mock
}

// Get retrieves a token from the cache
func (m *TokenCache) Get(key string) (string, bool) {
	args := m.Called(key)
	return args.String(0), args.Bool(1)
}

// Set stores a token in the cache
func (m *TokenCache) Set(key string, token string, ttl time.Duration) {
	m.Called(key, token, ttl)
}

// Delete removes a token from the cache
func (m *TokenCache) Delete(key string) {
	m.Called(key)
}

// Has checks if a token exists in the cache
func (m *TokenCache) Has(key string) bool {
	args := m.Called(key)
	return args.Bool(0)
}

// Blacklist is a testify mock for token blacklist operations
type Blacklist struct {
	mock.Mock
}

// IsBlacklisted checks if a token is blacklisted
func (m *Blacklist) IsBlacklisted(jti string) bool {
	args := m.Called(jti)
	return args.Bool(0)
}

// Add adds a token to the blacklist
func (m *Blacklist) Add(jti string, expiry time.Time) {
	m.Called(jti, expiry)
}

// Remove removes a token from the blacklist
func (m *Blacklist) Remove(jti string) {
	m.Called(jti)
}

// Cleanup removes expired entries from the blacklist
func (m *Blacklist) Cleanup() {
	m.Called()
}
