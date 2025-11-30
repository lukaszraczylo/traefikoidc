//go:build !yaegi

package features

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFeatureManager_Register(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	m.Register("TEST_FEATURE", "Test feature", false)

	if !m.flags["TEST_FEATURE"].enabled.Load() == false {
		t.Error("Expected feature to be disabled by default")
	}

	m.Register("TEST_ENABLED", "Test enabled feature", true)
	if m.flags["TEST_ENABLED"].enabled.Load() != true {
		t.Error("Expected feature to be enabled")
	}
}

func TestFeatureManager_IsEnabled(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	m.Register("TEST_FEATURE", "Test feature", true)

	if !m.IsEnabled("TEST_FEATURE") {
		t.Error("Expected feature to be enabled")
	}

	if m.IsEnabled("NON_EXISTENT") {
		t.Error("Expected non-existent feature to return false")
	}
}

func TestFeatureManager_EnableDisable(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	m.Register("TEST_FEATURE", "Test feature", false)

	// Enable the feature
	m.Enable("TEST_FEATURE")
	if !m.IsEnabled("TEST_FEATURE") {
		t.Error("Expected feature to be enabled")
	}

	// Disable the feature
	m.Disable("TEST_FEATURE")
	if m.IsEnabled("TEST_FEATURE") {
		t.Error("Expected feature to be disabled")
	}

	// Enable/Disable non-existent feature should not panic
	m.Enable("NON_EXISTENT")
	m.Disable("NON_EXISTENT")
}

func TestFeatureManager_Toggle(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	m.Register("TEST_FEATURE", "Test feature", false)

	// Toggle from false to true
	m.Toggle("TEST_FEATURE")
	if !m.IsEnabled("TEST_FEATURE") {
		t.Error("Expected feature to be enabled after toggle")
	}

	// Toggle from true to false
	m.Toggle("TEST_FEATURE")
	if m.IsEnabled("TEST_FEATURE") {
		t.Error("Expected feature to be disabled after toggle")
	}

	// Toggle non-existent feature should not panic
	m.Toggle("NON_EXISTENT")
}

func TestFeatureManager_OnChange(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	m.Register("TEST_FEATURE", "Test feature", false)

	var callbackCalled atomic.Bool
	var callbackValue atomic.Bool

	m.OnChange("TEST_FEATURE", func(enabled bool) {
		callbackCalled.Store(true)
		callbackValue.Store(enabled)
	})

	// Enable should trigger callback
	m.Enable("TEST_FEATURE")

	// Wait briefly for callback
	time.Sleep(10 * time.Millisecond)

	if !callbackCalled.Load() {
		t.Error("Expected callback to be called")
	}

	if !callbackValue.Load() {
		t.Error("Expected callback value to be true")
	}

	// Setting to same value should NOT trigger callback again
	callbackCalled.Store(false)
	m.Enable("TEST_FEATURE")
	time.Sleep(10 * time.Millisecond)

	if callbackCalled.Load() {
		t.Error("Expected callback NOT to be called when value doesn't change")
	}
}

func TestFeatureManager_LoadFromEnv(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	m.Register("TEST_FEATURE", "Test feature", false)
	m.Register("TEST_FEATURE_2", "Test feature 2", false)

	// Set environment variables
	os.Setenv("FEATURE_TEST_FEATURE", "true")
	os.Setenv("FEATURE_TEST_FEATURE_2", "1")
	defer func() {
		os.Unsetenv("FEATURE_TEST_FEATURE")
		os.Unsetenv("FEATURE_TEST_FEATURE_2")
	}()

	m.LoadFromEnv()

	if !m.IsEnabled("TEST_FEATURE") {
		t.Error("Expected TEST_FEATURE to be enabled from env")
	}

	if !m.IsEnabled("TEST_FEATURE_2") {
		t.Error("Expected TEST_FEATURE_2 to be enabled from env (value=1)")
	}
}

func TestFeatureManager_LoadFromEnv_FalseValues(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	m.Register("TEST_FEATURE", "Test feature", true) // Default true

	// Set to false
	os.Setenv("FEATURE_TEST_FEATURE", "false")
	defer os.Unsetenv("FEATURE_TEST_FEATURE")

	m.LoadFromEnv()

	if m.IsEnabled("TEST_FEATURE") {
		t.Error("Expected TEST_FEATURE to be disabled from env")
	}
}

func TestFeatureManager_GetAll(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	m.Register("FEATURE_1", "Feature 1", true)
	m.Register("FEATURE_2", "Feature 2", false)

	all := m.GetAll()

	if len(all) != 2 {
		t.Errorf("Expected 2 features, got %d", len(all))
	}

	if !all["FEATURE_1"] {
		t.Error("Expected FEATURE_1 to be enabled")
	}

	if all["FEATURE_2"] {
		t.Error("Expected FEATURE_2 to be disabled")
	}
}

func TestFeatureManager_Reset(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	m.Register("FEATURE_1", "Feature 1", true)
	m.Register("FEATURE_2", "Feature 2", true)

	var callbackCalled atomic.Int32
	m.OnChange("FEATURE_1", func(enabled bool) {
		callbackCalled.Add(1)
	})

	m.Reset()

	// All features should be disabled
	if m.IsEnabled("FEATURE_1") {
		t.Error("Expected FEATURE_1 to be disabled after reset")
	}

	if m.IsEnabled("FEATURE_2") {
		t.Error("Expected FEATURE_2 to be disabled after reset")
	}

	// Callbacks should be cleared
	m.Enable("FEATURE_1")
	time.Sleep(10 * time.Millisecond)

	if callbackCalled.Load() != 0 {
		t.Error("Expected callbacks to be cleared after reset")
	}
}

func TestGetManager_Singleton(t *testing.T) {
	// Reset global state for clean test
	managerOnce = sync.Once{}
	manager = nil

	m1 := GetManager()
	m2 := GetManager()

	if m1 != m2 {
		t.Error("Expected GetManager to return same instance")
	}
}

func TestGetManager_Initialize(t *testing.T) {
	// Reset global state for clean test
	managerOnce = sync.Once{}
	manager = nil

	m := GetManager()

	// Should have default feature flags
	all := m.GetAll()
	if len(all) < 6 {
		t.Errorf("Expected at least 6 default feature flags, got %d", len(all))
	}

	// Check specific flags exist
	flags := []string{
		UseUnifiedConfig,
		UseNewFileStructure,
		UseStandardErrors,
		UseEnhancedLogging,
		UseOptimizedTests,
		UseRedisRESP,
	}

	for _, flag := range flags {
		if _, exists := m.flags[flag]; !exists {
			t.Errorf("Expected default flag %s to exist", flag)
		}
	}
}

func TestHelperFunctions(t *testing.T) {
	// Reset global state
	managerOnce = sync.Once{}
	manager = nil

	// Test IsUnifiedConfigEnabled
	if IsUnifiedConfigEnabled() {
		t.Error("Expected unified config to be disabled by default")
	}

	GetManager().Enable(UseUnifiedConfig)
	if !IsUnifiedConfigEnabled() {
		t.Error("Expected unified config to be enabled")
	}

	// Reset for next test
	GetManager().Reset()

	// Test IsNewFileStructureEnabled
	if IsNewFileStructureEnabled() {
		t.Error("Expected new file structure to be disabled by default")
	}

	GetManager().Enable(UseNewFileStructure)
	if !IsNewFileStructureEnabled() {
		t.Error("Expected new file structure to be enabled")
	}

	// Test IsStandardErrorsEnabled
	GetManager().Reset()
	GetManager().Enable(UseStandardErrors)
	if !IsStandardErrorsEnabled() {
		t.Error("Expected standard errors to be enabled")
	}

	// Test IsEnhancedLoggingEnabled
	GetManager().Reset()
	GetManager().Enable(UseEnhancedLogging)
	if !IsEnhancedLoggingEnabled() {
		t.Error("Expected enhanced logging to be enabled")
	}

	// Test IsOptimizedTestsEnabled
	GetManager().Reset()
	GetManager().Enable(UseOptimizedTests)
	if !IsOptimizedTestsEnabled() {
		t.Error("Expected optimized tests to be enabled")
	}

	// Test IsRedisRESPEnabled
	GetManager().Reset()
	GetManager().Enable(UseRedisRESP)
	if !IsRedisRESPEnabled() {
		t.Error("Expected Redis RESP to be enabled")
	}
}

// Race condition tests
func TestFeatureManager_ConcurrentAccess(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	m.Register("TEST_FEATURE", "Test feature", false)

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent enables
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Enable("TEST_FEATURE")
		}()
	}

	// Concurrent disables
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Disable("TEST_FEATURE")
		}()
	}

	// Concurrent reads
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.IsEnabled("TEST_FEATURE")
		}()
	}

	wg.Wait()

	// Should not panic - final state is not deterministic but that's ok
}

func TestFeatureManager_ConcurrentCallbacks(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	m.Register("TEST_FEATURE", "Test feature", false)

	var callbackCount atomic.Int32
	var wg sync.WaitGroup

	// Register multiple callbacks concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.OnChange("TEST_FEATURE", func(enabled bool) {
				callbackCount.Add(1)
			})
		}()
	}

	wg.Wait()

	// Toggle the feature
	m.Toggle("TEST_FEATURE")

	// Wait for callbacks
	time.Sleep(50 * time.Millisecond)

	// All 10 callbacks should have been called
	if callbackCount.Load() != 10 {
		t.Errorf("Expected 10 callbacks, got %d", callbackCount.Load())
	}
}

func TestFeatureManager_ConcurrentGetAll(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	for i := 0; i < 5; i++ {
		m.Register(string(rune('A'+i)), "Feature", false)
	}

	var wg sync.WaitGroup

	// Concurrent GetAll calls
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			all := m.GetAll()
			if len(all) != 5 {
				t.Errorf("Expected 5 flags, got %d", len(all))
			}
		}()
	}

	// Concurrent modifications
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			flag := string(rune('A' + (idx % 5)))
			if idx%2 == 0 {
				m.Enable(flag)
			} else {
				m.Disable(flag)
			}
		}(i)
	}

	wg.Wait()
}

func TestFeatureManager_LoadFromEnv_Concurrent(t *testing.T) {
	m := &FeatureManager{
		flags: make(map[string]*FeatureFlag),
	}

	m.Register("FEATURE_1", "Feature 1", false)
	m.Register("FEATURE_2", "Feature 2", false)

	os.Setenv("FEATURE_FEATURE_1", "true")
	os.Setenv("FEATURE_FEATURE_2", "true")
	defer func() {
		os.Unsetenv("FEATURE_FEATURE_1")
		os.Unsetenv("FEATURE_FEATURE_2")
	}()

	var wg sync.WaitGroup

	// Load from env concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.LoadFromEnv()
		}()
	}

	wg.Wait()

	// Both should be enabled
	if !m.IsEnabled("FEATURE_1") || !m.IsEnabled("FEATURE_2") {
		t.Error("Expected features to be enabled from env")
	}
}
