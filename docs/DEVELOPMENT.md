# Development Guide

Guide for local development, testing, and contributing to the Traefik OIDC middleware.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Local Development Setup](#local-development-setup)
- [Running Tests](#running-tests)
- [Test Categories](#test-categories)
- [CI/CD Pipeline](#cicd-pipeline)
- [Code Quality](#code-quality)
- [Contributing](#contributing)

---

## Prerequisites

- **Go 1.23+** for plugin compilation
- **Docker & Docker Compose** for local testing
- **OIDC Provider** credentials (Google, Azure, etc.)

### Required Development Tools

```bash
# golangci-lint (comprehensive linting)
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# staticcheck (static analysis)
go install honnef.co/go/tools/cmd/staticcheck@latest

# gosec (security scanning)
go install github.com/securego/gosec/v2/cmd/gosec@latest

# govulncheck (vulnerability scanning)
go install golang.org/x/vuln/cmd/govulncheck@latest
```

---

## Local Development Setup

### Docker Compose Environment

The repository includes a Docker Compose setup for testing the plugin locally.

#### 1. Host Configuration

Add to `/etc/hosts`:

```bash
127.0.0.1 hello.localhost
127.0.0.1 traefik.localhost
```

#### 2. Plugin Configuration

The plugin is loaded using Traefik's **local plugins mode**:

- Plugin source: Parent directory (`../`)
- Mount path: `/plugins-local/src/github.com/lukaszraczylo/traefikoidc`
- Configuration: `experimental.localPlugins` in `traefik.yml`

#### 3. OIDC Provider Setup

Edit `docker/dynamic.yml` with your provider details:

**Google:**
```yaml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefikoidc:
          providerURL: "https://accounts.google.com"
          clientID: "your-client-id.apps.googleusercontent.com"
          clientSecret: "your-google-client-secret"
          sessionEncryptionKey: "your-32-character-encryption-key"
          callbackURL: "/oauth2/callback"
          logoutURL: "/oauth2/logout"
          scopes:
            - "openid"
            - "email"
            - "profile"
```

**Azure AD:**
```yaml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefikoidc:
          providerURL: "https://login.microsoftonline.com/your-tenant-id/v2.0"
          clientID: "your-azure-client-id"
          clientSecret: "your-azure-client-secret"
          sessionEncryptionKey: "your-32-character-encryption-key"
          callbackURL: "/oauth2/callback"
          scopes:
            - "openid"
            - "email"
            - "profile"
```

#### 4. Start Environment

```bash
cd docker
docker-compose up -d
```

#### 5. Test Plugin

- **Protected App**: http://hello.localhost (redirects to OIDC)
- **Traefik Dashboard**: http://traefik.localhost:8080

### Development Workflow

1. **Edit plugin code** in the project root
2. **Build and test** (optional syntax check):
   ```bash
   go mod tidy
   go build .
   go test ./...
   ```
3. **Restart Traefik** to reload plugin:
   ```bash
   docker-compose restart traefik
   ```
4. **Test changes** at http://hello.localhost

### Debugging

**View plugin logs:**
```bash
docker-compose logs -f traefik | grep traefikoidc
```

**Check plugin loading:**
```bash
docker-compose logs traefik | grep -i plugin
```

**Verify plugin directory:**
```bash
docker-compose exec traefik ls -la /plugins-local/src/github.com/lukaszraczylo/traefikoidc/
```

---

## Running Tests

### Quick Start

```bash
# Fast development testing (< 30 seconds)
go test ./... -short

# Standard tests with race detector
go test -race -timeout=15m ./...

# With coverage report
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

### Test Modes

| Mode | Command | Duration | Use Case |
|------|---------|----------|----------|
| Quick | `go test ./... -short` | < 30s | During development |
| Extended | `RUN_EXTENDED_TESTS=1 go test ./...` | 2-5 min | Before commits |
| Long | `RUN_LONG_TESTS=1 go test ./...` | 5-15 min | Release validation |
| Stress | `RUN_STRESS_TESTS=1 go test ./...` | 10-30 min | Performance testing |

### Environment Variables

```bash
# Enable specific test types
export RUN_EXTENDED_TESTS=1
export RUN_LONG_TESTS=1
export RUN_STRESS_TESTS=1

# Disable specific features
export DISABLE_LEAK_DETECTION=1

# Customize test parameters
export TEST_MAX_CONCURRENCY=10
export TEST_MAX_ITERATIONS=50
export TEST_MEMORY_THRESHOLD_MB=25.5
```

---

## Test Categories

### Quick Tests (Default)

- Basic functionality verification
- Limited iterations (1-3)
- Small data sets
- Essential memory leak checks

**Configuration:**
- Max Iterations: 3
- Max Concurrency: 5
- Memory Threshold: 2.0 MB
- Timeout: 10 seconds

### Extended Tests

- Comprehensive testing before commits
- More iterations (5-10)
- Enhanced memory leak detection

**Configuration:**
- Max Iterations: 10
- Max Concurrency: 20
- Memory Threshold: 10.0 MB
- Timeout: 30 seconds

### Long Tests

- Performance validation
- High iteration counts (50-100)
- Large data sets

**Configuration:**
- Max Iterations: 100
- Max Concurrency: 50
- Memory Threshold: 50.0 MB
- Timeout: 60 seconds

### Stress Tests

- Maximum load testing
- Edge case validation
- Extreme parameters

**Configuration:**
- Max Iterations: 500
- Max Concurrency: 100
- Memory Threshold: 100.0 MB
- Timeout: 120 seconds

### Running Specific Test Suites

```bash
# Memory leak tests
go test -v -run='.*Leak.*' ./...

# Integration tests
go test -v -run='.*Integration.*' ./...

# Regression tests
go test -v -run='.*Regression.*' ./...

# Provider-specific tests
go test -v -run='.*Azure.*' ./...
go test -v -run='.*Google.*' ./...
```

### Benchmarks

```bash
# Quick benchmarks
go test -bench=. -short

# Extended benchmarks
RUN_EXTENDED_TESTS=1 go test -bench=.

# Memory profiling
go test -bench=. -memprofile=mem.prof
go tool pprof mem.prof
```

---

## CI/CD Pipeline

The repository uses GitHub Actions for comprehensive validation with 20+ parallel checks.

### Triggered On

- Pull requests to `main` branch
- Pushes to `main` branch

### Parallel Jobs

#### Code Quality (3 checks)
- **Format & Basic Checks** - gofmt, go vet, go mod
- **golangci-lint** - 30+ linters
- **Staticcheck** - Advanced static analysis

#### Security (3 checks)
- **Gosec** - Security vulnerability scanning
- **Govulncheck** - Go vulnerability database
- **CodeQL** - GitHub's semantic code analysis

#### Testing (9 suites)
- Race Detector
- Coverage (75% threshold)
- Memory Leaks
- Integration Tests
- Regression Tests
- Security Edge Cases
- Session Tests
- Token Tests
- CSRF Tests

#### Provider Testing (9 providers)
Tests run in parallel for:
- Google
- Azure AD
- Auth0
- Okta
- Keycloak
- AWS Cognito
- GitLab
- GitHub
- Generic OIDC

#### Performance & Build (3 checks)
- Benchmarks
- Multi-platform Build (linux/darwin x amd64/arm64)
- Go Version Compatibility (Go 1.23 & 1.24)

### Quality Gates

All PRs must pass:
- All parallel checks
- 75% test coverage minimum
- Zero security vulnerabilities
- No race conditions
- No memory leaks
- All providers tested
- Builds on all platforms

---

## Code Quality

### Pre-Commit Checklist

```bash
# Run before every commit
gofmt -s -w . && \
go mod tidy && \
golangci-lint run && \
go test -race -short ./... && \
echo "Ready to commit!"
```

### Local Validation

```bash
# Format code
gofmt -s -w .

# Run linter
golangci-lint run

# Static analysis
staticcheck ./...

# Security scan
gosec ./...

# Vulnerability check
govulncheck ./...

# Tests with race detector
go test -race -timeout=15m -count=1 ./...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# View coverage in browser
go tool cover -html=coverage.out
```

### Troubleshooting

**Coverage Below Threshold:**
```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out  # See uncovered lines
```

**Race Condition Found:**
```bash
go test -race -v -run=TestName ./...
```

**Linter Errors:**
```bash
golangci-lint run -v
golangci-lint run --fix  # Auto-fix some issues
```

**Provider Test Fails:**
```bash
go test -v -run='.*Azure.*' ./...
```

---

## Contributing

### Development Guidelines

1. **Memory Management**: Ensure all goroutines can be cancelled and resources are bounded
2. **Testing**: Add tests for new features, including memory leak tests where appropriate
3. **Race Conditions**: Run tests with `-race` flag to detect race conditions
4. **Documentation**: Update README and configuration files for new options

### Pull Request Template

PRs should include:
- Description of changes
- Type of change (bug fix, feature, breaking change, etc.)
- Related issues
- Provider impact (which providers are affected)
- Testing performed
- Security considerations
- Performance impact
- Breaking changes (if any)

### Checklist

Before submitting:
- [ ] Code follows project style
- [ ] Self-review completed
- [ ] Tests added for new functionality
- [ ] All tests pass locally
- [ ] Documentation updated
- [ ] No new warnings generated

### Code Owners

The repository uses CODEOWNERS for automatic PR reviewer assignment based on file paths.

### Dependabot

Automated dependency updates run weekly (Mondays 9 AM) with security updates prioritized.

---

## Additional Resources

- [golangci-lint Rules](.golangci.yml)
- [PR Template](.github/PULL_REQUEST_TEMPLATE.md)
- [Workflow Documentation](.github/workflows/README.md)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
