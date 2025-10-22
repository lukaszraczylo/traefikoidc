// Package features provides feature flag management for safe rollback during refactoring
package features

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// FeatureFlag represents a feature flag for controlling new functionality
type FeatureFlag struct {
	name        string
	description string
	enabled     atomic.Bool
	mu          sync.RWMutex
	callbacks   []func(bool)
}

// FeatureManager manages all feature flags in the application
type FeatureManager struct {
	flags map[string]*FeatureFlag
	mu    sync.RWMutex
}

var (
	// Global feature manager instance
	manager     *FeatureManager
	managerOnce sync.Once
)

// Feature flag names
const (
	// UseUnifiedConfig enables the new unified configuration system
	UseUnifiedConfig = "USE_UNIFIED_CONFIG"

	// UseNewFileStructure enables the new modularized file structure
	UseNewFileStructure = "USE_NEW_FILE_STRUCTURE"

	// UseStandardErrors enables the standardized error package
	UseStandardErrors = "USE_STANDARD_ERRORS"

	// UseEnhancedLogging enables the enhanced logging system
	UseEnhancedLogging = "USE_ENHANCED_LOGGING"

	// UseOptimizedTests enables the consolidated test suite
	UseOptimizedTests = "USE_OPTIMIZED_TESTS"

	// UseRedisRESP enables the custom Redis RESP implementation
	UseRedisRESP = "USE_REDIS_RESP"
)

// GetManager returns the global feature manager instance
func GetManager() *FeatureManager {
	managerOnce.Do(func() {
		manager = &FeatureManager{
			flags: make(map[string]*FeatureFlag),
		}
		manager.initialize()
	})
	return manager
}

// initialize sets up default feature flags
func (m *FeatureManager) initialize() {
	// Phase 0: Feature flags setup
	m.Register(UseUnifiedConfig, "Enable unified configuration package", false)
	m.Register(UseNewFileStructure, "Enable modularized file structure", false)
	m.Register(UseStandardErrors, "Enable standardized error handling", false)
	m.Register(UseEnhancedLogging, "Enable enhanced logging system", false)
	m.Register(UseOptimizedTests, "Enable optimized test suite", false)
	m.Register(UseRedisRESP, "Enable custom Redis RESP implementation", false)

	// Load from environment variables
	m.LoadFromEnv()
}

// Register creates a new feature flag
func (m *FeatureManager) Register(name, description string, defaultValue bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	flag := &FeatureFlag{
		name:        name,
		description: description,
		callbacks:   make([]func(bool), 0),
	}
	flag.enabled.Store(defaultValue)
	m.flags[name] = flag
}

// IsEnabled checks if a feature flag is enabled
func (m *FeatureManager) IsEnabled(name string) bool {
	m.mu.RLock()
	flag, exists := m.flags[name]
	m.mu.RUnlock()

	if !exists {
		return false
	}

	return flag.enabled.Load()
}

// Enable turns on a feature flag
func (m *FeatureManager) Enable(name string) {
	m.setFlag(name, true)
}

// Disable turns off a feature flag
func (m *FeatureManager) Disable(name string) {
	m.setFlag(name, false)
}

// Toggle switches a feature flag state
func (m *FeatureManager) Toggle(name string) {
	m.mu.RLock()
	flag, exists := m.flags[name]
	m.mu.RUnlock()

	if exists {
		newValue := !flag.enabled.Load()
		m.setFlag(name, newValue)
	}
}

// setFlag updates a feature flag value and triggers callbacks
func (m *FeatureManager) setFlag(name string, value bool) {
	m.mu.RLock()
	flag, exists := m.flags[name]
	m.mu.RUnlock()

	if !exists {
		return
	}

	oldValue := flag.enabled.Swap(value)

	// Only trigger callbacks if value actually changed
	if oldValue != value {
		flag.mu.RLock()
		callbacks := flag.callbacks
		flag.mu.RUnlock()

		for _, callback := range callbacks {
			callback(value)
		}
	}
}

// OnChange registers a callback to be called when a feature flag changes
func (m *FeatureManager) OnChange(name string, callback func(bool)) {
	m.mu.RLock()
	flag, exists := m.flags[name]
	m.mu.RUnlock()

	if exists {
		flag.mu.Lock()
		flag.callbacks = append(flag.callbacks, callback)
		flag.mu.Unlock()
	}
}

// LoadFromEnv loads feature flag values from environment variables
func (m *FeatureManager) LoadFromEnv() {
	m.mu.RLock()
	flags := make(map[string]*FeatureFlag)
	for name, flag := range m.flags {
		flags[name] = flag
	}
	m.mu.RUnlock()

	for name, flag := range flags {
		envVar := "FEATURE_" + name
		if value := os.Getenv(envVar); value != "" {
			enabled := strings.ToLower(value) == "true" || value == "1"
			flag.enabled.Store(enabled)
		}
	}
}

// GetAll returns all feature flags and their states
func (m *FeatureManager) GetAll() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]bool)
	for name, flag := range m.flags {
		result[name] = flag.enabled.Load()
	}
	return result
}

// Reset resets all feature flags to their default values
func (m *FeatureManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, flag := range m.flags {
		flag.enabled.Store(false)
		flag.callbacks = make([]func(bool), 0)
	}
}

// Helper functions for common checks

// IsUnifiedConfigEnabled checks if unified config is enabled
func IsUnifiedConfigEnabled() bool {
	return GetManager().IsEnabled(UseUnifiedConfig)
}

// IsNewFileStructureEnabled checks if new file structure is enabled
func IsNewFileStructureEnabled() bool {
	return GetManager().IsEnabled(UseNewFileStructure)
}

// IsStandardErrorsEnabled checks if standard errors are enabled
func IsStandardErrorsEnabled() bool {
	return GetManager().IsEnabled(UseStandardErrors)
}

// IsEnhancedLoggingEnabled checks if enhanced logging is enabled
func IsEnhancedLoggingEnabled() bool {
	return GetManager().IsEnabled(UseEnhancedLogging)
}

// IsOptimizedTestsEnabled checks if optimized tests are enabled
func IsOptimizedTestsEnabled() bool {
	return GetManager().IsEnabled(UseOptimizedTests)
}

// IsRedisRESPEnabled checks if custom Redis RESP is enabled
func IsRedisRESPEnabled() bool {
	return GetManager().IsEnabled(UseRedisRESP)
}
