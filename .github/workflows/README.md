# GitHub Actions Workflows

This directory contains CI/CD workflows for the Traefik OIDC middleware.

## Workflows

### PR Validation (`pr-validation.yml`)

A comprehensive validation workflow that runs **all checks in parallel** for maximum speed and thorough testing.

**Triggered on:**
- Pull requests to `main` branch
- Pushes to `main` branch

**Parallel Jobs (20+ concurrent checks):**

#### Code Quality
- **Quick Checks** - Format, go vet, go mod verify
- **golangci-lint** - Comprehensive linting
- **Staticcheck** - Static analysis

#### Security
- **Gosec** - Security vulnerability scanning
- **Govulncheck** - Go vulnerability database check
- **CodeQL** - GitHub's code analysis

#### Testing
- **Race Detector** - Concurrent access bug detection
- **Coverage** - Test coverage with 75% threshold
- **Memory Leaks** - Goroutine and memory leak detection
- **Integration Tests** - Full integration test suite
- **Regression Tests** - Prevent previously fixed bugs
- **Security Edge Cases** - Security-specific scenarios
- **Session Tests** - Session management validation
- **Token Tests** - Token validation scenarios
- **CSRF Tests** - CSRF protection validation

#### Provider Testing (Matrix)
Tests run in parallel for each OIDC provider:
- Google
- Azure AD
- Auth0
- Okta
- Keycloak
- AWS Cognito
- GitLab
- GitHub
- Generic OIDC

#### Performance & Compatibility
- **Benchmarks** - Performance regression detection
- **Build Matrix** - linux/darwin × amd64/arm64
- **Go Versions** - Go 1.23 and 1.24 compatibility

#### Final Validation
- **All Checks Passed** - Ensures all jobs succeeded

## Workflow Features

### 🚀 Parallel Execution
All independent checks run simultaneously for fastest feedback (~5-10 minutes for full suite).

### 📊 Coverage Reporting
- Automatic PR comments with coverage statistics
- Per-package coverage breakdown
- 75% coverage threshold enforcement

### 🔒 Security First
- Multiple security scanners (gosec, govulncheck, CodeQL)
- SARIF report uploads for GitHub Security tab
- Security edge case testing

### 🎯 Comprehensive Testing
- Race condition detection
- Memory leak detection
- Provider-specific testing
- Integration and regression tests

### 📈 Performance Tracking
- Benchmark results stored as artifacts
- Performance regression detection

### ✅ Quality Gates
All checks must pass before PR can be merged:
- Code formatting and style
- Security vulnerabilities
- Test coverage threshold
- Race conditions
- Memory leaks
- Build success on all platforms

## Local Development

### Run checks locally before pushing:

```bash
# Format code
gofmt -s -w .

# Run linter
golangci-lint run

# Run tests with race detector
go test -race -timeout=15m -count=1 ./...

# Check coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# Run specific test suites
go test -v -run='.*Leak.*' ./...           # Memory leak tests
go test -v -run='.*Integration.*' ./...    # Integration tests
go test -v -run='.*Regression.*' ./...     # Regression tests

# Run benchmarks
go test -bench=. -benchmem ./...

# Security scan
gosec ./...
govulncheck ./...
```

### Required Tools

Install these tools for local development:

```bash
# golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# staticcheck
go install honnef.co/go/tools/cmd/staticcheck@latest

# gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
```

## Troubleshooting

### Workflow Fails

1. **Check job status** - Click on failed job for details
2. **Review logs** - Expand failed steps to see error messages
3. **Run locally** - Reproduce issue with local commands above
4. **Check coverage** - Ensure test coverage meets 75% threshold

### Coverage Below Threshold

Add tests to increase coverage:
```bash
# See which lines aren't covered
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Race Condition Detected

Run with race detector locally:
```bash
go test -race -v ./...
```

### Provider Test Failure

Test specific provider:
```bash
go test -v -run='.*Azure.*' ./internal/providers/...
```

## Performance Optimization

The workflow is optimized for speed:

- **Parallel execution** - All independent jobs run simultaneously
- **Go caching** - Dependencies cached between runs
- **Strategic ordering** - Quick checks run first for fast feedback
- **Fail-fast disabled** - Continue running all tests even if some fail

## Workflow Monitoring

### GitHub Actions Dashboard
Monitor workflow runs at: `https://github.com/{owner}/{repo}/actions`

### Status Badges
Add to README.md:
```markdown
![PR Validation](https://github.com/{owner}/{repo}/actions/workflows/pr-validation.yml/badge.svg)
```

### Notifications
Configure in repository settings:
- Settings → Notifications
- Choose email or Slack notifications for workflow failures

## Maintenance

### Update Go Version
Edit in workflow file:
```yaml
go-version: '1.24'  # Update this
```

### Adjust Coverage Threshold
Edit in workflow file:
```yaml
THRESHOLD=75  # Adjust this value
```

### Add New Provider
Add to provider matrix:
```yaml
matrix:
  provider:
    - new_provider  # Add here
```

## Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [golangci-lint Configuration](../.golangci.yml)
- [Dependabot Configuration](../dependabot.yml)
- [PR Template](../PULL_REQUEST_TEMPLATE.md)
