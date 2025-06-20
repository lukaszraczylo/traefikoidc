package traefikoidc

import (
	"reflect"
	"testing"
)

func TestMergeScopes(t *testing.T) {
	testCases := []struct {
		name           string
		defaultScopes  []string
		userScopes     []string
		expectedScopes []string
	}{
		{
			name:           "Empty user scopes",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{},
			expectedScopes: []string{"openid", "profile", "email"},
		},
		{
			name:           "Non-overlapping scopes",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"roles", "custom_scope"},
			expectedScopes: []string{"openid", "profile", "email", "roles", "custom_scope"},
		},
		{
			name:           "Overlapping scopes",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     []string{"openid", "roles", "profile", "permissions"},
			expectedScopes: []string{"openid", "profile", "email", "roles", "permissions"},
		},
		{
			name:           "Nil user scopes",
			defaultScopes:  []string{"openid", "profile", "email"},
			userScopes:     nil,
			expectedScopes: []string{"openid", "profile", "email"},
		},
		{
			name:           "Nil default scopes",
			defaultScopes:  nil,
			userScopes:     []string{"roles", "custom_scope"},
			expectedScopes: []string{"roles", "custom_scope"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := mergeScopes(tc.defaultScopes, tc.userScopes)
			if !reflect.DeepEqual(result, tc.expectedScopes) {
				t.Errorf("Expected %v, got %v", tc.expectedScopes, result)
			}
		})
	}
}

func TestScopesConfiguration(t *testing.T) {
	defaultScopes := []string{"openid", "profile", "email"}
	userScopes := []string{"roles", "custom_scope"}

	t.Run("Default Append Behavior", func(t *testing.T) {
		// Create config with user scopes but overrideScopes=false
		config := &Config{
			Scopes:         userScopes,
			OverrideScopes: false,
		}

		// Simulate middleware initialization
		var result []string
		if config.OverrideScopes {
			result = append([]string(nil), config.Scopes...)
		} else {
			result = mergeScopes(defaultScopes, config.Scopes)
		}

		// Expect defaultScopes + userScopes with deduplication
		expectedScopes := []string{"openid", "profile", "email", "roles", "custom_scope"}
		if !reflect.DeepEqual(result, expectedScopes) {
			t.Errorf("Expected %v, got %v", expectedScopes, result)
		}
	})

	t.Run("Override Behavior", func(t *testing.T) {
		// Create config with user scopes and overrideScopes=true
		config := &Config{
			Scopes:         userScopes,
			OverrideScopes: true,
		}

		// Simulate middleware initialization
		var result []string
		if config.OverrideScopes {
			result = append([]string(nil), config.Scopes...)
		} else {
			result = mergeScopes(defaultScopes, config.Scopes)
		}

		// Expect only userScopes
		if !reflect.DeepEqual(result, userScopes) {
			t.Errorf("Expected %v, got %v", userScopes, result)
		}
	})

	t.Run("Empty Scopes with Override", func(t *testing.T) {
		// Create config with empty scopes and overrideScopes=true
		config := &Config{
			Scopes:         []string{},
			OverrideScopes: true,
		}

		// Simulate middleware initialization
		var result []string
		if config.OverrideScopes {
			result = append([]string(nil), config.Scopes...)
		} else {
			result = mergeScopes(defaultScopes, config.Scopes)
		}

		// Expect empty scopes - check length instead of DeepEqual
		if len(result) != 0 {
			t.Errorf("Expected empty slice, got %v with length %d", result, len(result))
		}
	})
}
