package traefikoidc

import (
	"net/url"
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

func TestDeduplicateScopes(t *testing.T) {
	testCases := []struct {
		name           string
		inputScopes    []string
		expectedScopes []string
	}{
		{
			name:           "No duplicates",
			inputScopes:    []string{"openid", "profile", "email"},
			expectedScopes: []string{"openid", "profile", "email"},
		},
		{
			name:           "Simple duplicates",
			inputScopes:    []string{"openid", "profile", "openid", "email"},
			expectedScopes: []string{"openid", "profile", "email"},
		},
		{
			name:           "Multiple duplicates",
			inputScopes:    []string{"scope1", "scope2", "scope1", "scope2", "scope1"},
			expectedScopes: []string{"scope1", "scope2"},
		},
		{
			name:           "Empty input",
			inputScopes:    []string{},
			expectedScopes: []string{},
		},
		{
			name:           "Nil input",
			inputScopes:    nil,
			expectedScopes: []string{},
		},
		{
			name:           "Single element",
			inputScopes:    []string{"openid"},
			expectedScopes: []string{"openid"},
		},
		{
			name:           "All duplicates",
			inputScopes:    []string{"test", "test", "test"},
			expectedScopes: []string{"test"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := deduplicateScopes(tc.inputScopes)
			if !reflect.DeepEqual(result, tc.expectedScopes) {
				t.Errorf("Expected %v, got %v", tc.expectedScopes, result)
			}
		})
	}
}

func TestScopesConfiguration(t *testing.T) {
	defaultScopes := []string{"openid", "profile", "email"}

	testCases := []struct {
		name           string
		configScopes   []string
		expectedResult []string
		overrideScopes bool
	}{
		{
			name:           "Default Append Behavior - No user scopes",
			configScopes:   []string{},
			overrideScopes: false,
			expectedResult: []string{"openid", "profile", "email"},
		},
		{
			name:           "Default Append Behavior - With user scopes",
			configScopes:   []string{"roles", "custom_scope"},
			overrideScopes: false,
			expectedResult: []string{"openid", "profile", "email", "roles", "custom_scope"},
		},
		{
			name:           "Default Append Behavior - With duplicate user scopes",
			configScopes:   []string{"roles", "custom_scope", "roles"},
			overrideScopes: false,
			expectedResult: []string{"openid", "profile", "email", "roles", "custom_scope"},
		},
		{
			name:           "Default Append Behavior - User scopes overlap with defaults",
			configScopes:   []string{"openid", "roles", "profile"},
			overrideScopes: false,
			expectedResult: []string{"openid", "profile", "email", "roles"},
		},
		{
			name:           "Override Behavior - With user scopes",
			configScopes:   []string{"roles", "custom_scope"},
			overrideScopes: true,
			expectedResult: []string{"roles", "custom_scope"},
		},
		{
			name:           "Override Behavior - With duplicate user scopes",
			configScopes:   []string{"roles", "custom_scope", "roles"},
			overrideScopes: true,
			expectedResult: []string{"roles", "custom_scope"},
		},
		{
			name:           "Override Behavior - Empty user scopes",
			configScopes:   []string{},
			overrideScopes: true,
			expectedResult: []string{},
		},
		{
			name:           "Override Behavior - Nil user scopes",
			configScopes:   nil,
			overrideScopes: true,
			expectedResult: []string{}, // Deduplicate will handle nil as empty
		},
		{
			name:           "Override Behavior - Single user scope",
			configScopes:   []string{"email"},
			overrideScopes: true,
			expectedResult: []string{"email"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the logic within TraefikOidc.New for setting t.scopes
			var result []string
			uniqueConfigScopes := deduplicateScopes(tc.configScopes)
			if tc.overrideScopes {
				result = uniqueConfigScopes
			} else {
				result = mergeScopes(defaultScopes, uniqueConfigScopes)
			}

			if !reflect.DeepEqual(result, tc.expectedResult) {
				t.Errorf("Expected scopes %v, got %v", tc.expectedResult, result)
			}
		})
	}
}

func TestBuildAuthURLScopeHandling(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup() // Basic setup for TraefikOidc instance

	// Default scopes expected if not overridden and no user scopes provided
	defaultInitialScopes := []string{"openid", "profile", "email"}

	testCases := []struct {
		expectedParams      map[string]string
		name                string
		expectedScopeString string
		configScopes        []string
		overrideScopes      bool
		isGoogle            bool
		isAzure             bool
	}{
		{
			name:                "Deduplication: Default append, duplicate in user scopes",
			configScopes:        []string{"openid", "custom", "profile", "custom"},
			overrideScopes:      false,
			expectedScopeString: "openid profile email custom offline_access",
		},
		{
			name:                "Deduplication: Override, duplicate in user scopes",
			configScopes:        []string{"openid", "custom", "profile", "custom"},
			overrideScopes:      true,
			expectedScopeString: "openid custom profile", // offline_access not added
		},
		{
			name:                "Override True: No automatic offline_access",
			configScopes:        []string{"scope1", "scope2"},
			overrideScopes:      true,
			expectedScopeString: "scope1 scope2",
		},
		{
			name:                "Override True: User includes offline_access",
			configScopes:        []string{"scope1", "offline_access", "scope2"},
			overrideScopes:      true,
			expectedScopeString: "scope1 offline_access scope2",
		},
		{
			name:                "Override False: Automatic offline_access added",
			configScopes:        []string{"scope1", "scope2"},
			overrideScopes:      false,
			expectedScopeString: "openid profile email scope1 scope2 offline_access",
		},
		{
			name:                "Override False: User includes offline_access (deduplicated)",
			configScopes:        []string{"scope1", "offline_access", "scope2"},
			overrideScopes:      false,
			expectedScopeString: "openid profile email scope1 offline_access scope2",
		},
		{
			name:                "Integration: Duplicate scopes in config, override true",
			configScopes:        []string{"scope1", "scope1", "scope2"},
			overrideScopes:      true,
			expectedScopeString: "scope1 scope2",
		},
		{
			name:                "Integration: No auto offline_access with override true",
			configScopes:        []string{"scope1", "scope2"},
			overrideScopes:      true,
			expectedScopeString: "scope1 scope2",
		},
		{
			name:                "Integration: Duplicates and no auto offline_access with override true",
			configScopes:        []string{"scope1", "scope1", "scope2"},
			overrideScopes:      true,
			expectedScopeString: "scope1 scope2",
		},
		{
			name:                "Integration: Google provider, override false, no user scopes",
			configScopes:        []string{},
			overrideScopes:      false,
			isGoogle:            true,
			expectedScopeString: "openid profile email", // Google uses access_type=offline param
			expectedParams:      map[string]string{"access_type": "offline", "prompt": "consent"},
		},
		{
			name:                "Integration: Google provider, override true, user scopes",
			configScopes:        []string{"custom1", "custom2"},
			overrideScopes:      true,
			isGoogle:            true,
			expectedScopeString: "custom1 custom2", // Google uses access_type=offline param
			expectedParams:      map[string]string{"access_type": "offline", "prompt": "consent"},
		},
		{
			name:                "Integration: Azure provider, override false, no user scopes",
			configScopes:        []string{},
			overrideScopes:      false,
			isAzure:             true,
			expectedScopeString: "openid profile email offline_access", // Azure adds offline_access scope
			expectedParams:      map[string]string{"response_mode": "query"},
		},
		{
			name:                "Integration: Azure provider, override true, user scopes without offline_access",
			configScopes:        []string{"custom1", "custom2"},
			overrideScopes:      true,
			isAzure:             true,
			expectedScopeString: "custom1 custom2", // Azure respects override
			expectedParams:      map[string]string{"response_mode": "query"},
		},
		{
			name:                "Integration: Azure provider, override true, user scopes with offline_access",
			configScopes:        []string{"custom1", "offline_access"},
			overrideScopes:      true,
			isAzure:             true,
			expectedScopeString: "custom1 offline_access", // Azure respects override
			expectedParams:      map[string]string{"response_mode": "query"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the TraefikOidc instance's scope initialization
			var initializedScopes []string
			uniqueConfigScopes := deduplicateScopes(tc.configScopes)
			if tc.overrideScopes {
				initializedScopes = uniqueConfigScopes
			} else {
				initializedScopes = mergeScopes(defaultInitialScopes, uniqueConfigScopes)
			}

			// Create a new TraefikOidc instance for this test case
			// to ensure proper isolation of 'scopes' and 'overrideScopes' fields.
			// We use parts of the TestSuite's tOidc for common setup like logger, clientID etc.
			// but override the scope-related fields.
			testOidc := &TraefikOidc{
				clientID:       ts.tOidc.clientID,
				logger:         ts.tOidc.logger,
				scopes:         initializedScopes, // Use scopes processed as New() would
				overrideScopes: tc.overrideScopes,
				// Set other necessary fields for buildAuthURL to function
				authURL:    "https://provider.com/auth", // Dummy authURL
				issuerURL:  "https://provider.com",      // Dummy issuerURL
				httpClient: ts.tOidc.httpClient,         // Reuse from TestSuite
			}

			originalIssuerURL := testOidc.issuerURL
			if tc.isGoogle {
				testOidc.issuerURL = "https://accounts.google.com"
			} else if tc.isAzure {
				testOidc.issuerURL = "https://login.microsoftonline.com/common"
			}

			authURLString := testOidc.buildAuthURL("http://localhost/callback", "state", "nonce", "challenge")
			parsedURL, err := url.Parse(authURLString)
			if err != nil {
				t.Fatalf("Failed to parse auth URL: %v", err)
			}

			query := parsedURL.Query()
			actualScopeString := query.Get("scope")

			if actualScopeString != tc.expectedScopeString {
				t.Errorf("Expected scope string %q, got %q", tc.expectedScopeString, actualScopeString)
			}

			if tc.expectedParams != nil {
				for k, v := range tc.expectedParams {
					if query.Get(k) != v {
						t.Errorf("Expected param %s=%s, got %s", k, v, query.Get(k))
					}
				}
			}
			testOidc.issuerURL = originalIssuerURL // Restore
		})
	}
}
