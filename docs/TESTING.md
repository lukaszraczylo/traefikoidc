# Testing Guide

Comprehensive testing infrastructure for traefikoidc.

## Overview

| Metric | Value |
|--------|-------|
| Test files | 97 |
| Lines of test code | ~63,500 |
| Code coverage | 70.3% |
| Race conditions | None (all pass with `-race`) |

## Running Tests

```bash
# Run all tests
go test ./...

# Run with race detection
go test -race ./...

# Run with coverage
go test -cover ./...

# Run specific test suite
go test -v -run "TokenValidationSuite" .

# Run edge case tests
go test -v -run "ClockSkewEdgeCasesSuite|UnicodeClaimsSuite" .
```

## Test Infrastructure

### Directory Structure

```
internal/testutil/
├── compat.go              # Re-exports for main package access
├── mocks/
│   ├── interfaces.go      # JWKCache, TokenExchanger, TokenVerifier, etc.
│   ├── session.go         # SessionManager, SessionData
│   ├── cache.go           # Cache, TokenCache, Blacklist
│   └── interfaces_test.go # Mock verification tests
├── fixtures/
│   └── tokens.go          # JWT token generation fixtures
└── servers/
    ├── oidc.go            # Mock OIDC server factory
    └── oidc_test.go       # Server tests
```

### Test Suites

| Suite | File | Description |
|-------|------|-------------|
| TokenValidationSuite | `token_validation_suite_test.go` | Token validation happy path and error cases |
| JWKCacheTestSuite | `token_validation_suite_test.go` | JWK cache behavior tests |
| TokenExchangerTestSuite | `token_validation_suite_test.go` | Token exchange scenarios |
| ClockSkewEdgeCasesSuite | `edge_cases_suite_test.go` | Expiry boundary testing |
| UnicodeClaimsSuite | `edge_cases_suite_test.go` | Unicode/emoji handling in claims |
| LargeClaimsSuite | `edge_cases_suite_test.go` | Large data handling (100s of claims) |
| URLPathEdgeCasesSuite | `edge_cases_suite_test.go` | URL parsing edge cases |
| ConcurrencyEdgeCasesSuite | `edge_cases_suite_test.go` | Concurrent token validation |
| ExampleTestSuite | `testutil_example_test.go` | Example demonstrating patterns |

## Mock Types

The project provides two mocking patterns:

### State-Based Mocks (Basic)

Located in `main_test.go`, `mocks_test.go`. Simple mocks that store data in struct fields.

| Mock | Interface | Description |
|------|-----------|-------------|
| `MockJWKCache` | `JWKCacheInterface` | Simple state-based mock with JWKS/Err fields |
| `MockTokenVerifier` | `TokenVerifier` | Function-based mock for token verification |
| `MockTokenExchanger` | `TokenExchanger` | Function-based mock for token exchange |
| `MockOAuthProvider` | `http.Handler` | Full HTTP handler mock for OAuth provider simulation |
| `MockSessionManager` | `SessionManager` | State-based mock for session management |
| `MockHTTPClient` | N/A | Mock HTTP client with customizable responses |

**Usage:**
```go
mock := &MockJWKCache{
    JWKS: &JWKSet{Keys: []JWK{jwk}},
    Err:  nil,
}
tOidc := &TraefikOidc{
    jwkCache: mock,
    // ...
}
```

### Enhanced State-Based Mocks (with Call Tracking)

Located in `enhanced_mocks_test.go`. State-based mocks with built-in call tracking and assertion helpers.

| Mock | Interface | Description |
|------|-----------|-------------|
| `EnhancedMockJWKCache` | `JWKCacheInterface` | State-based with call tracking |
| `EnhancedMockTokenVerifier` | `TokenVerifier` | State-based with call tracking |
| `EnhancedMockTokenExchanger` | `TokenExchanger` | State-based with call tracking |
| `EnhancedMockCacheInterface` | `CacheInterface` | Functional cache with call tracking |

**Usage:**
```go
mock := &EnhancedMockJWKCache{
    JWKS: &JWKSet{Keys: []JWK{jwk}},
}

// Make calls
result, err := mock.GetJWKS(ctx, "https://example.com/jwks", nil)

// Verify calls were made
mock.AssertGetJWKSCalled(t)
mock.AssertGetJWKSCalledWith(t, "https://example.com/jwks")
mock.AssertGetJWKSCallCount(t, 1)

// Access call details
s.Equal(1, mock.GetJWKSCallCount())
```

**Features:**
- Track all calls with parameters and timestamps
- Built-in assertion helpers using testify
- Thread-safe for concurrent tests
- `Reset()` method to clear state between tests
- `LastCall()` to inspect most recent call

### Testify-Based Mocks

Located in `testify_mocks_test.go`. Mocks using testify's `.On()/.Return()` pattern for behavior verification.

| Mock | Interface | Description |
|------|-----------|-------------|
| `TestifyJWKCache` | `JWKCacheInterface` | Testify mock with `.On()/.Return()` |
| `TestifyTokenVerifier` | `TokenVerifier` | Testify mock for token verification |
| `TestifyTokenExchanger` | `TokenExchanger` | Testify mock for token exchange |
| `TestifyCacheInterface` | `CacheInterface` | Testify mock for cache operations |
| `TestifyHTTPClient` | N/A | Testify mock for HTTP client |
| `TestifyRoundTripper` | `http.RoundTripper` | Testify mock for HTTP transport |

**Usage:**
```go
mock := &TestifyJWKCache{}
mock.On("GetJWKS", mock.Anything, "https://example.com/jwks", mock.Anything).
    Return(&JWKSet{Keys: []JWK{jwk}}, nil)

// After test
mock.AssertExpectations(t)
```

### Testutil Package Mocks

Located in `internal/testutil/mocks/`. Generic mocks for testing the test infrastructure itself.

```go
import "github.com/lukaszraczylo/traefikoidc/internal/testutil"

mock := testutil.NewJWKCacheMock()
mock.On("GetJWKS", mock.Anything, mock.Anything, mock.Anything).
    Return(&mocks.JWKSet{Keys: []mocks.JWK{{Kty: "RSA"}}}, nil)
```

### Choosing the Right Mock

| Use Case | Recommended Mock |
|----------|-----------------|
| Simple return values only | Basic state-based (`MockJWKCache`) |
| Return values + verify calls made | Enhanced state-based (`EnhancedMockJWKCache`) |
| Complex call expectations | Testify-based (`TestifyJWKCache`) |
| Verify call order/sequence | Testify-based |
| HTTP endpoint simulation | `MockOAuthProvider` |
| New testify suite tests | Enhanced or Testify-based |

**Decision Guide:**

1. **Basic State-Based**: Use when you only need to control return values and don't care about verifying interactions.

2. **Enhanced State-Based**: Use when you want to verify calls were made with specific parameters, but prefer simpler setup than testify's `.On()/.Return()` pattern.

3. **Testify-Based**: Use when you need complex behavior like different returns per call, strict call ordering, or detailed expectation matching.

## Token Fixtures

The `testutil.TokenFixture` generates JWT tokens for testing:

```go
fixture, err := testutil.NewTokenFixture()

// Valid token with default claims
token, _ := fixture.ValidToken(nil)

// Token with custom claims
token, _ := fixture.ValidToken(map[string]interface{}{
    "email": "test@example.com",
    "roles": []string{"admin"},
})

// Expired token
token, _ := fixture.ExpiredToken()

// Token with specific roles/groups
token, _ := fixture.TokenWithRoles([]string{"admin", "user"})
token, _ := fixture.TokenWithGroups([]string{"developers"})

// Token with clock skew
token, _ := fixture.TokenWithSkew(-2 * time.Minute)  // expired 2 min ago
token, _ := fixture.TokenWithSkew(5 * time.Minute)   // expires in 5 min

// Token missing specific claims
token, _ := fixture.TokenMissingClaim("email", "sub")

// Malformed token
token := fixture.MalformedToken()  // "not.a.valid.jwt"

// Get JWKS for verification
jwks := fixture.GetJWKS()
```

## Mock OIDC Server

The `testutil.OIDCServer` provides a fully functional mock OIDC provider:

```go
// Default configuration
server := testutil.NewOIDCServer(nil)
defer server.Close()

// Custom configuration
config := testutil.DefaultServerConfig()
config.Issuer = "https://custom-issuer.com"
config.TokenError = &testutil.OIDCError{
    Error:       "invalid_grant",
    Description: "Authorization code expired",
}
server := testutil.NewOIDCServer(config)

// Provider-specific configurations
googleConfig := testutil.GoogleServerConfig()
azureConfig := testutil.AzureServerConfig()
auth0Config := testutil.Auth0ServerConfig()
keycloakConfig := testutil.KeycloakServerConfig()

// Behavior configurations
slowConfig := testutil.SlowServerConfig(100 * time.Millisecond)
rateLimitedConfig := testutil.RateLimitedServerConfig(5)  // Limit after 5 requests
```

### Server Endpoints

| Endpoint | Description |
|----------|-------------|
| `/.well-known/openid-configuration` | OIDC discovery document |
| `/authorize` | Authorization endpoint |
| `/token` | Token exchange endpoint |
| `/jwks` | JSON Web Key Set |
| `/userinfo` | User information endpoint |
| `/introspect` | Token introspection |
| `/revoke` | Token revocation |
| `/logout` | End session endpoint |

### Request Tracking

```go
server := testutil.NewOIDCServer(nil)

// Make requests...

count := server.GetRequestCount()
requests := server.GetRequests()
server.Reset()  // Clear tracking
```

## Writing Test Suites

### Basic Suite Structure

```go
type MyTestSuite struct {
    suite.Suite

    fixture *testutil.TokenFixture
    tOidc   *TraefikOidc
}

func (s *MyTestSuite) SetupSuite() {
    var err error
    s.fixture, err = testutil.NewTokenFixture()
    s.Require().NoError(err)
}

func (s *MyTestSuite) SetupTest() {
    // Per-test setup
    s.tOidc = &TraefikOidc{
        issuerURL: s.fixture.Issuer,
        // ...
    }
}

func (s *MyTestSuite) TearDownTest() {
    // Per-test cleanup
}

func (s *MyTestSuite) TestSomething() {
    token, err := s.fixture.ValidToken(nil)
    s.Require().NoError(err)

    err = s.tOidc.VerifyToken(token)
    s.NoError(err)
}

func TestMyTestSuite(t *testing.T) {
    suite.Run(t, new(MyTestSuite))
}
```

### Table-Driven Tests

```go
func (s *MyTestSuite) TestClockSkewEdgeCases() {
    testCases := []struct {
        name       string
        skew       time.Duration
        shouldPass bool
    }{
        {"valid_token", 5 * time.Minute, true},
        {"expired_within_tolerance", -1 * time.Minute, true},
        {"expired_beyond_tolerance", -10 * time.Minute, false},
    }

    for _, tc := range testCases {
        s.Run(tc.name, func() {
            token, err := s.fixture.TokenWithSkew(tc.skew)
            s.Require().NoError(err)

            err = s.tOidc.VerifyToken(token)
            if tc.shouldPass {
                s.NoError(err)
            } else {
                s.Error(err)
            }
        })
    }
}
```

## Test Categories

### Happy Path Tests

Test the expected successful scenarios:

- Valid token verification
- Successful token exchange
- Session creation and retrieval
- Cache operations

### Error Case Tests

Test failure scenarios:

- Expired tokens
- Invalid signatures
- Wrong issuer/audience
- Network failures
- Rate limiting

### Edge Case Tests

Test boundary conditions:

- Clock skew tolerance boundaries
- Unicode/emoji in claims
- Very large claim values
- Concurrent access
- Special characters in URLs

## Best Practices

1. **Use fixtures for token generation** - Don't manually construct JWTs
2. **Use mock servers for integration tests** - Test against realistic OIDC behavior
3. **Always run with `-race`** - Catch concurrency issues early
4. **Use testify assertions** - Better error messages and cleaner code
5. **Clean up resources** - Use `t.Cleanup()` or `TearDownTest()`
6. **Test edge cases systematically** - Use table-driven tests
