// Package compat provides backward compatibility layer during refactoring
package compat

import (
	"fmt"
	"reflect"
	"sync"
)

// CompatibilityLayer provides backward compatibility during the migration
type CompatibilityLayer struct {
	mappings     map[string]string // old path -> new path
	converters   map[string]Converter
	deprecations map[string]string // deprecated field -> warning message
	mu           sync.RWMutex
}

// Converter is a function that converts old value format to new format
type Converter func(oldValue interface{}) (newValue interface{}, err error)

// Global compatibility layer instance
var (
	layer     *CompatibilityLayer
	layerOnce sync.Once
)

// GetLayer returns the global compatibility layer instance
func GetLayer() *CompatibilityLayer {
	layerOnce.Do(func() {
		layer = &CompatibilityLayer{
			mappings:     make(map[string]string),
			converters:   make(map[string]Converter),
			deprecations: make(map[string]string),
		}
		layer.initialize()
	})
	return layer
}

// initialize sets up default compatibility mappings
func (c *CompatibilityLayer) initialize() {
	// Configuration path mappings (old -> new)
	c.RegisterMapping("ProviderURL", "Provider.IssuerURL")
	c.RegisterMapping("ClientID", "Provider.ClientID")
	c.RegisterMapping("ClientSecret", "Provider.ClientSecret")
	c.RegisterMapping("CallbackURL", "Provider.RedirectURL")
	c.RegisterMapping("LogoutURL", "Provider.LogoutURL")
	c.RegisterMapping("SessionEncryptionKey", "Session.EncryptionKey")
	c.RegisterMapping("Scopes", "Provider.Scopes")
	c.RegisterMapping("RateLimit", "Middleware.RateLimit")
	c.RegisterMapping("RefreshGracePeriodSeconds", "Token.RefreshGracePeriod")

	// Redis configuration mappings
	c.RegisterMapping("RedisAddr", "Redis.Addresses[0]")
	c.RegisterMapping("RedisPassword", "Redis.Password")
	c.RegisterMapping("RedisDB", "Redis.DB")

	// Session configuration mappings
	c.RegisterMapping("SessionName", "Session.Name")
	c.RegisterMapping("SessionMaxAge", "Session.MaxAge")
	c.RegisterMapping("SessionSecret", "Session.Secret")
	c.RegisterMapping("SessionChunkSize", "Session.ChunkSize")

	// Security configuration mappings
	c.RegisterMapping("ForceHTTPS", "Security.ForceHTTPS")
	c.RegisterMapping("EnablePKCE", "Security.EnablePKCE")
	c.RegisterMapping("AllowedUsers", "Security.AllowedUsers")
	c.RegisterMapping("AllowedUserDomains", "Security.AllowedUserDomains")
	c.RegisterMapping("AllowedRolesAndGroups", "Security.AllowedRolesAndGroups")
	c.RegisterMapping("ExcludedURLs", "Security.ExcludedURLs")

	// Register converters for complex transformations
	c.RegisterConverter("RefreshGracePeriodSeconds", func(oldValue interface{}) (interface{}, error) {
		// Convert seconds (int) to duration string
		if seconds, ok := oldValue.(int); ok {
			return fmt.Sprintf("%ds", seconds), nil
		}
		return oldValue, nil
	})

	// Register deprecations
	c.RegisterDeprecation("LogLevel", "LogLevel is deprecated, use Logging.Level instead")
	c.RegisterDeprecation("HTTPClient", "HTTPClient is deprecated, configure via Transport settings")
}

// RegisterMapping registers a field mapping from old to new path
func (c *CompatibilityLayer) RegisterMapping(oldPath, newPath string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mappings[oldPath] = newPath
}

// RegisterConverter registers a value converter for a field
func (c *CompatibilityLayer) RegisterConverter(field string, converter Converter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.converters[field] = converter
}

// RegisterDeprecation registers a deprecation warning for a field
func (c *CompatibilityLayer) RegisterDeprecation(field, message string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deprecations[field] = message
}

// GetMapping returns the new path for an old configuration path
func (c *CompatibilityLayer) GetMapping(oldPath string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	newPath, exists := c.mappings[oldPath]
	return newPath, exists
}

// Convert applies conversion logic to a value
func (c *CompatibilityLayer) Convert(field string, value interface{}) (interface{}, error) {
	c.mu.RLock()
	converter, exists := c.converters[field]
	c.mu.RUnlock()

	if !exists {
		return value, nil
	}

	return converter(value)
}

// CheckDeprecation checks if a field is deprecated and returns warning message
func (c *CompatibilityLayer) CheckDeprecation(field string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	message, deprecated := c.deprecations[field]
	return message, deprecated
}

// MigrateMap migrates an old configuration map to new structure
func (c *CompatibilityLayer) MigrateMap(oldConfig map[string]interface{}) (map[string]interface{}, []string) {
	newConfig := make(map[string]interface{})
	warnings := []string{}

	for key, value := range oldConfig {
		// Check for deprecation
		if warning, deprecated := c.CheckDeprecation(key); deprecated {
			warnings = append(warnings, warning)
		}

		// Get new path
		newPath, hasMappming := c.GetMapping(key)
		if !hasMappming {
			// No mapping, use as-is
			newConfig[key] = value
			continue
		}

		// Apply converter if exists
		convertedValue, err := c.Convert(key, value)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Failed to convert %s: %v", key, err))
			convertedValue = value
		}

		// Set value at new path
		setNestedValue(newConfig, newPath, convertedValue)
	}

	return newConfig, warnings
}

// setNestedValue sets a value in a nested map structure using dot notation
func setNestedValue(m map[string]interface{}, path string, value interface{}) {
	keys := splitPath(path)
	if len(keys) == 0 {
		return
	}

	current := m
	for i := 0; i < len(keys)-1; i++ {
		key := keys[i]

		// Check if this key has array notation
		if isArrayPath(key) {
			// Handle array notation (e.g., "Addresses[0]")
			continue // Skip array handling for now, will be handled in actual migration
		}

		if _, exists := current[key]; !exists {
			current[key] = make(map[string]interface{})
		}

		// Ensure it's a map
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			// Can't traverse further, create new map
			newMap := make(map[string]interface{})
			current[key] = newMap
			current = newMap
		}
	}

	// Set the final value
	finalKey := keys[len(keys)-1]
	current[finalKey] = value
}

// splitPath splits a configuration path into segments
func splitPath(path string) []string {
	segments := []string{}
	current := ""

	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			if current != "" {
				segments = append(segments, current)
				current = ""
			}
		} else {
			current += string(path[i])
		}
	}

	if current != "" {
		segments = append(segments, current)
	}

	return segments
}

// isArrayPath checks if a path segment contains array notation
func isArrayPath(segment string) bool {
	for _, char := range segment {
		if char == '[' {
			return true
		}
	}
	return false
}

// ConfigAdapter provides an adapter interface for old code to work with new config
type ConfigAdapter struct {
	newConfig interface{}
	oldPaths  map[string]func() interface{}
	mu        sync.RWMutex
}

// NewConfigAdapter creates a new configuration adapter
func NewConfigAdapter(newConfig interface{}) *ConfigAdapter {
	adapter := &ConfigAdapter{
		newConfig: newConfig,
		oldPaths:  make(map[string]func() interface{}),
	}
	return adapter
}

// RegisterGetter registers a getter function for an old path
func (a *ConfigAdapter) RegisterGetter(oldPath string, getter func() interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.oldPaths[oldPath] = getter
}

// Get retrieves a value using old path notation
func (a *ConfigAdapter) Get(oldPath string) (interface{}, bool) {
	a.mu.RLock()
	getter, exists := a.oldPaths[oldPath]
	a.mu.RUnlock()

	if !exists {
		// Try to get from new config using reflection
		return a.getFromNewConfig(oldPath)
	}

	return getter(), true
}

// getFromNewConfig attempts to retrieve value from new config using reflection
func (a *ConfigAdapter) getFromNewConfig(path string) (interface{}, bool) {
	// Check if there's a mapping for this path
	compat := GetLayer()
	if newPath, hasMappming := compat.GetMapping(path); hasMappming {
		return a.getNestedField(newPath)
	}

	// Try direct access
	return a.getNestedField(path)
}

// getNestedField retrieves a nested field value using reflection
func (a *ConfigAdapter) getNestedField(path string) (interface{}, bool) {
	segments := splitPath(path)
	if len(segments) == 0 {
		return nil, false
	}

	v := reflect.ValueOf(a.newConfig)

	// Dereference pointer if needed
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	for _, segment := range segments {
		if v.Kind() != reflect.Struct {
			return nil, false
		}

		field := v.FieldByName(segment)
		if !field.IsValid() {
			return nil, false
		}

		v = field
	}

	if v.IsValid() && v.CanInterface() {
		return v.Interface(), true
	}

	return nil, false
}
