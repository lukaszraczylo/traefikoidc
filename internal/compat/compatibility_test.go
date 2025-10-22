//go:build !yaegi

package compat

import (
	"sync"
	"testing"
)

func TestGetLayer_Singleton(t *testing.T) {
	// Reset global state
	layerOnce = sync.Once{}
	layer = nil

	layer1 := GetLayer()
	layer2 := GetLayer()

	if layer1 != layer2 {
		t.Error("Expected GetLayer to return same instance")
	}
}

func TestGetLayer_Initialize(t *testing.T) {
	// Reset global state
	layerOnce = sync.Once{}
	layer = nil

	l := GetLayer()

	// Check default mappings exist
	if _, exists := l.GetMapping("ProviderURL"); !exists {
		t.Error("Expected ProviderURL mapping to exist")
	}

	if _, exists := l.GetMapping("ClientID"); !exists {
		t.Error("Expected ClientID mapping to exist")
	}

	// Check deprecations exist
	if _, deprecated := l.CheckDeprecation("LogLevel"); !deprecated {
		t.Error("Expected LogLevel to be marked deprecated")
	}
}

func TestRegisterMapping(t *testing.T) {
	l := &CompatibilityLayer{
		mappings:     make(map[string]string),
		converters:   make(map[string]Converter),
		deprecations: make(map[string]string),
	}

	l.RegisterMapping("OldField", "New.Field")

	newPath, exists := l.GetMapping("OldField")
	if !exists {
		t.Error("Expected mapping to exist")
	}

	if newPath != "New.Field" {
		t.Errorf("Expected 'New.Field', got '%s'", newPath)
	}
}

func TestRegisterConverter(t *testing.T) {
	l := &CompatibilityLayer{
		mappings:     make(map[string]string),
		converters:   make(map[string]Converter),
		deprecations: make(map[string]string),
	}

	converter := func(oldValue interface{}) (interface{}, error) {
		if str, ok := oldValue.(string); ok {
			return str + "_converted", nil
		}
		return oldValue, nil
	}

	l.RegisterConverter("TestField", converter)

	result, err := l.Convert("TestField", "test")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if result != "test_converted" {
		t.Errorf("Expected 'test_converted', got '%v'", result)
	}
}

func TestConvert_NoConverter(t *testing.T) {
	l := &CompatibilityLayer{
		mappings:     make(map[string]string),
		converters:   make(map[string]Converter),
		deprecations: make(map[string]string),
	}

	// No converter registered
	result, err := l.Convert("UnknownField", "value")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if result != "value" {
		t.Error("Expected original value when no converter exists")
	}
}

func TestRegisterDeprecation(t *testing.T) {
	l := &CompatibilityLayer{
		mappings:     make(map[string]string),
		converters:   make(map[string]Converter),
		deprecations: make(map[string]string),
	}

	l.RegisterDeprecation("OldField", "This field is deprecated")

	message, deprecated := l.CheckDeprecation("OldField")
	if !deprecated {
		t.Error("Expected field to be deprecated")
	}

	if message != "This field is deprecated" {
		t.Errorf("Expected deprecation message, got '%s'", message)
	}
}

func TestCheckDeprecation_NotDeprecated(t *testing.T) {
	l := &CompatibilityLayer{
		mappings:     make(map[string]string),
		converters:   make(map[string]Converter),
		deprecations: make(map[string]string),
	}

	_, deprecated := l.CheckDeprecation("NewField")
	if deprecated {
		t.Error("Expected field not to be deprecated")
	}
}

func TestMigrateMap_BasicMapping(t *testing.T) {
	l := &CompatibilityLayer{
		mappings:     make(map[string]string),
		converters:   make(map[string]Converter),
		deprecations: make(map[string]string),
	}

	l.RegisterMapping("OldField", "New.Field")

	oldConfig := map[string]interface{}{
		"OldField": "value123",
	}

	newConfig, warnings := l.MigrateMap(oldConfig)

	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}

	// Check nested structure
	if newMap, ok := newConfig["New"].(map[string]interface{}); ok {
		if val, exists := newMap["Field"]; !exists || val != "value123" {
			t.Errorf("Expected nested field value 'value123', got %v", val)
		}
	} else {
		t.Error("Expected nested map structure")
	}
}

func TestMigrateMap_WithDeprecation(t *testing.T) {
	l := &CompatibilityLayer{
		mappings:     make(map[string]string),
		converters:   make(map[string]Converter),
		deprecations: make(map[string]string),
	}

	l.RegisterMapping("DeprecatedField", "New.Field")
	l.RegisterDeprecation("DeprecatedField", "Field is deprecated")

	oldConfig := map[string]interface{}{
		"DeprecatedField": "value",
	}

	_, warnings := l.MigrateMap(oldConfig)

	if len(warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d", len(warnings))
	}

	if warnings[0] != "Field is deprecated" {
		t.Errorf("Expected deprecation warning, got '%s'", warnings[0])
	}
}

func TestMigrateMap_WithConverter(t *testing.T) {
	l := &CompatibilityLayer{
		mappings:     make(map[string]string),
		converters:   make(map[string]Converter),
		deprecations: make(map[string]string),
	}

	l.RegisterMapping("Seconds", "Duration")
	l.RegisterConverter("Seconds", func(oldValue interface{}) (interface{}, error) {
		if seconds, ok := oldValue.(int); ok {
			return seconds * 1000, nil // Convert to milliseconds
		}
		return oldValue, nil
	})

	oldConfig := map[string]interface{}{
		"Seconds": 60,
	}

	newConfig, _ := l.MigrateMap(oldConfig)

	if val, ok := newConfig["Duration"]; !ok || val != 60000 {
		t.Errorf("Expected Duration to be 60000, got %v", val)
	}
}

func TestMigrateMap_NoMapping(t *testing.T) {
	l := &CompatibilityLayer{
		mappings:     make(map[string]string),
		converters:   make(map[string]Converter),
		deprecations: make(map[string]string),
	}

	oldConfig := map[string]interface{}{
		"UnmappedField": "value",
	}

	newConfig, _ := l.MigrateMap(oldConfig)

	if val, ok := newConfig["UnmappedField"]; !ok || val != "value" {
		t.Error("Expected unmapped field to be copied as-is")
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		path     string
		expected []string
	}{
		{"Simple", []string{"Simple"}},
		{"Nested.Path", []string{"Nested", "Path"}},
		{"Deep.Nested.Path", []string{"Deep", "Nested", "Path"}},
		{"", []string{}},
		{"Single", []string{"Single"}},
	}

	for _, tt := range tests {
		result := splitPath(tt.path)
		if len(result) != len(tt.expected) {
			t.Errorf("Path '%s': expected %d segments, got %d", tt.path, len(tt.expected), len(result))
			continue
		}

		for i, segment := range result {
			if segment != tt.expected[i] {
				t.Errorf("Path '%s': segment %d expected '%s', got '%s'", tt.path, i, tt.expected[i], segment)
			}
		}
	}
}

func TestIsArrayPath(t *testing.T) {
	tests := []struct {
		segment  string
		expected bool
	}{
		{"Addresses[0]", true},
		{"Items[5]", true},
		{"Simple", false},
		{"NoArray", false},
		{"[start", true},
	}

	for _, tt := range tests {
		result := isArrayPath(tt.segment)
		if result != tt.expected {
			t.Errorf("Segment '%s': expected %v, got %v", tt.segment, tt.expected, result)
		}
	}
}

func TestSetNestedValue_SingleLevel(t *testing.T) {
	m := make(map[string]interface{})
	setNestedValue(m, "Field", "value")

	if val, ok := m["Field"]; !ok || val != "value" {
		t.Error("Expected single level field to be set")
	}
}

func TestSetNestedValue_MultiLevel(t *testing.T) {
	m := make(map[string]interface{})
	setNestedValue(m, "Parent.Child", "value")

	parent, ok := m["Parent"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected Parent to be a map")
	}

	if val, ok := parent["Child"]; !ok || val != "value" {
		t.Error("Expected nested field to be set")
	}
}

func TestSetNestedValue_DeepNesting(t *testing.T) {
	m := make(map[string]interface{})
	setNestedValue(m, "Level1.Level2.Level3", "deep_value")

	level1, ok := m["Level1"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected Level1 to be a map")
	}

	level2, ok := level1["Level2"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected Level2 to be a map")
	}

	if val, ok := level2["Level3"]; !ok || val != "deep_value" {
		t.Error("Expected deeply nested field to be set")
	}
}

// ConfigAdapter tests

func TestNewConfigAdapter(t *testing.T) {
	config := map[string]interface{}{"key": "value"}
	adapter := NewConfigAdapter(config)

	if adapter == nil {
		t.Fatal("Expected adapter to be created")
	}

	if adapter.newConfig == nil {
		t.Error("Expected config to be stored")
	}
}

func TestConfigAdapter_RegisterGetter(t *testing.T) {
	adapter := NewConfigAdapter(nil)

	called := false
	adapter.RegisterGetter("TestPath", func() interface{} {
		called = true
		return "test_value"
	})

	val, exists := adapter.Get("TestPath")
	if !exists {
		t.Error("Expected getter to exist")
	}

	if val != "test_value" {
		t.Errorf("Expected 'test_value', got %v", val)
	}

	if !called {
		t.Error("Expected getter function to be called")
	}
}

type TestConfig struct {
	Provider struct {
		IssuerURL string
		ClientID  string
	}
	Session struct {
		EncryptionKey string
	}
}

func TestConfigAdapter_GetNestedField(t *testing.T) {
	config := &TestConfig{}
	config.Provider.IssuerURL = "https://test.com"
	config.Provider.ClientID = "test-client"
	config.Session.EncryptionKey = "secret123"

	adapter := NewConfigAdapter(config)

	// Test nested field access
	val, exists := adapter.getNestedField("Provider.IssuerURL")
	if !exists {
		t.Error("Expected field to exist")
	}

	if val != "https://test.com" {
		t.Errorf("Expected 'https://test.com', got %v", val)
	}

	// Test another nested field
	val2, exists2 := adapter.getNestedField("Provider.ClientID")
	if !exists2 || val2 != "test-client" {
		t.Error("Expected ClientID to be accessible")
	}

	// Test non-existent field
	_, exists3 := adapter.getNestedField("NonExistent.Field")
	if exists3 {
		t.Error("Expected non-existent field to return false")
	}
}

// Race condition tests

func TestCompatibilityLayer_ConcurrentAccess(t *testing.T) {
	l := &CompatibilityLayer{
		mappings:     make(map[string]string),
		converters:   make(map[string]Converter),
		deprecations: make(map[string]string),
	}

	var wg sync.WaitGroup

	// Concurrent registrations
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			l.RegisterMapping(string(rune('A'+idx%26)), "New.Field")
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _ = l.GetMapping(string(rune('A' + idx%26)))
		}(i)
	}

	wg.Wait()
}

func TestCompatibilityLayer_ConcurrentMigrate(t *testing.T) {
	l := &CompatibilityLayer{
		mappings:     make(map[string]string),
		converters:   make(map[string]Converter),
		deprecations: make(map[string]string),
	}

	l.RegisterMapping("OldField", "New.Field")

	var wg sync.WaitGroup

	// Concurrent migrations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			oldConfig := map[string]interface{}{
				"OldField": "value",
			}
			_, _ = l.MigrateMap(oldConfig)
		}()
	}

	wg.Wait()
}

func TestConfigAdapter_ConcurrentAccess(t *testing.T) {
	config := &TestConfig{}
	config.Provider.IssuerURL = "https://test.com"

	adapter := NewConfigAdapter(config)

	var wg sync.WaitGroup

	// Concurrent getter registrations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			path := string(rune('A' + idx%26))
			adapter.RegisterGetter(path, func() interface{} {
				return "value"
			})
		}(i)
	}

	// Concurrent gets
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			path := string(rune('A' + idx%26))
			_, _ = adapter.Get(path)
		}(i)
	}

	wg.Wait()
}
