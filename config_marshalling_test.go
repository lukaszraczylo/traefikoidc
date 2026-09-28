package traefikoidc

import (
	"reflect"
	"strings"
	"testing"
)

// TestConfigToMap_IncludesAllJSONFields pins FIX-40: configToMap is the
// single field/redaction list shared by MarshalJSON and MarshalYAML (R150),
// so every json-tagged Config field must appear as a configToMap key or the
// marshaled/logged config silently drops it again. Fields tagged
// `json:"-"` are intentionally excluded from marshaling and are skipped.
func TestConfigToMap_IncludesAllJSONFields(t *testing.T) {
	// Non-nil pointer fields so their conditional branches in configToMap
	// run and populate a map key, matching how a real, non-empty Config is
	// built.
	cfg := Config{
		Redis:                     &RedisConfig{},
		DynamicClientRegistration: &DynamicClientRegistrationConfig{},
		SecurityHeaders:           &SecurityHeadersConfig{},
	}
	result := cfg.configToMap()

	typ := reflect.TypeOf(Config{})
	var missing []string
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			continue
		}
		if _, ok := result[name]; !ok {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		t.Fatalf("configToMap is missing json-tagged Config fields: %v", missing)
	}
}
