package utils

import (
	"reflect"
	"testing"
)

func TestCreateStringMap(t *testing.T) {
	items := []string{"apple", "banana", "cherry"}
	result := CreateStringMap(items)

	expected := map[string]struct{}{
		"apple":  {},
		"banana": {},
		"cherry": {},
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestCreateCaseInsensitiveStringMap(t *testing.T) {
	items := []string{"Apple", "BANANA", "Cherry"}
	result := CreateCaseInsensitiveStringMap(items)

	expected := map[string]struct{}{
		"apple":  {},
		"banana": {},
		"cherry": {},
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestDeduplicateScopes(t *testing.T) {
	scopes := []string{"openid", "profile", "email", "openid", "profile"}
	result := DeduplicateScopes(scopes)

	expected := []string{"openid", "profile", "email"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestMergeScopes(t *testing.T) {
	defaultScopes := []string{"openid", "profile"}
	userScopes := []string{"email", "offline_access"}
	result := MergeScopes(defaultScopes, userScopes)

	expected := []string{"openid", "profile", "email", "offline_access"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestMergeScopesWithDuplicates(t *testing.T) {
	defaultScopes := []string{"openid", "profile"}
	userScopes := []string{"profile", "email", "openid"}
	result := MergeScopes(defaultScopes, userScopes)

	expected := []string{"openid", "profile", "email"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestMergeScopesEmptyUserScopes(t *testing.T) {
	defaultScopes := []string{"openid", "profile"}
	userScopes := []string{}
	result := MergeScopes(defaultScopes, userScopes)

	expected := []string{"openid", "profile"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestKeysFromMap(t *testing.T) {
	m := map[string]struct{}{
		"key1": {},
		"key2": {},
		"key3": {},
	}
	result := KeysFromMap(m)

	// Since map iteration order is not guaranteed, we need to check length and presence
	if len(result) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(result))
	}

	resultMap := make(map[string]bool)
	for _, key := range result {
		resultMap[key] = true
	}

	expectedKeys := []string{"key1", "key2", "key3"}
	for _, key := range expectedKeys {
		if !resultMap[key] {
			t.Errorf("Expected key %s not found in result", key)
		}
	}
}

func TestBuildFullURL(t *testing.T) {
	tests := []struct {
		scheme   string
		host     string
		path     string
		expected string
	}{
		{"https", "example.com", "/path", "https://example.com/path"},
		{"http", "localhost:8080", "/callback", "http://localhost:8080/callback"},
		{"https", "test.example.com", "/auth/callback", "https://test.example.com/auth/callback"},
	}

	for _, test := range tests {
		result := BuildFullURL(test.scheme, test.host, test.path)
		if result != test.expected {
			t.Errorf("For scheme=%s, host=%s, path=%s: expected %s, got %s",
				test.scheme, test.host, test.path, test.expected, result)
		}
	}
}
