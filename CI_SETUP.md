# CI/CD Setup Guide

## 📋 Overview

This repository now has a comprehensive CI/CD pipeline that runs **20+ parallel checks** on every pull request to ensure code quality, security, and reliability.

## 🎯 What Was Added

### GitHub Actions Workflow
- **`.github/workflows/pr-validation.yml`** - Main CI/CD pipeline (single file, all parallel)

### Configuration Files
- **`.golangci.yml`** - Linter configuration with 30+ enabled checks
- **`.github/dependabot.yml`** - Automated dependency updates
- **`.github/CODEOWNERS`** - Automatic PR reviewer assignment
- **`.github/PULL_REQUEST_TEMPLATE.md`** - Standardized PR descriptions
- **`.github/workflows/README.md`** - Detailed workflow documentation
- **`.github/workflows/.gitattributes`** - Consistent line endings

## ✅ What Gets Tested (All in Parallel)

### Code Quality (3 checks)
- **Format & Basic Checks** - gofmt, go vet, go mod
- **golangci-lint** - 30+ linters including style, complexity, bugs
- **Staticcheck** - Advanced static analysis

### Security (3 checks)
- **Gosec** - Security vulnerability scanning with SARIF reports
- **Govulncheck** - Go vulnerability database scanning
- **CodeQL** - GitHub's semantic code analysis

### Testing (9 test suites)
- **Race Detector** - Concurrent access bugs
- **Coverage** - 75% threshold with PR comments
- **Memory Leaks** - Goroutine and memory leak detection
- **Integration Tests** - Full integration suite
- **Regression Tests** - Prevent old bugs from returning
- **Security Edge Cases** - Security-specific scenarios
- **Session Tests** - Session management
- **Token Tests** - Token validation
- **CSRF Tests** - CSRF protection

### Provider Testing (9 providers in parallel)
- Google, Azure AD, Auth0, Okta, Keycloak, AWS Cognito, GitLab, GitHub, Generic

### Performance & Build (3 checks)
- **Benchmarks** - Performance regression detection
- **Multi-platform Build** - 4 combinations (linux/darwin × amd64/arm64)
- **Go Version Compatibility** - Go 1.23 & 1.24

## 🚀 Quick Start

### 1. Push to GitHub
```bash
git add .github .golangci.yml CI_SETUP.md
git commit -m "Add comprehensive CI/CD pipeline"
git push origin main
```

### 2. Create a Test PR
```bash
# Create a feature branch
git checkout -b feature/test-ci
echo "# Test" >> test.md
git add test.md
git commit -m "Test CI pipeline"
git push origin feature/test-ci

# Create PR on GitHub
# Watch all 20+ checks run in parallel! ⚡
```

### 3. Monitor Results
- Go to Actions tab: `https://github.com/{owner}/{repo}/actions`
- Click on latest workflow run
- See all parallel checks in action
- Review coverage comment on PR

## 📊 Key Features

### ⚡ Maximum Speed
- **Parallel execution** - All checks run simultaneously
- **Smart caching** - Go modules and build cache
- **Optimized order** - Quick checks first for fast feedback
- **Expected runtime**: 5-10 minutes for full suite

### 🔒 Security First
- **3 security scanners** - gosec, govulncheck, CodeQL
- **SARIF integration** - Results in GitHub Security tab
- **Dependency scanning** - Automated with Dependabot
- **Security edge case tests**

### 📈 Coverage Tracking
- **Automatic PR comments** with coverage stats
- **Per-package breakdown** included
- **75% threshold** enforced (configurable)
- **Codecov integration** ready (optional)

### 🎨 Developer Experience
- **Clear PR template** guides contributors
- **Auto code owners** assignment
- **Detailed error messages** for failures
- **Benchmark tracking** for performance

## 🛠️ Local Development

### Install Required Tools
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

### Run Checks Locally
```bash
# Quick validation (before committing)
gofmt -s -w .                    # Format code
go vet ./...                     # Basic checks
go mod tidy                      # Clean dependencies

# Linting
golangci-lint run                # Full lint suite
staticcheck ./...                # Static analysis

# Testing
go test -race -timeout=15m ./... # Tests with race detector
go test -coverprofile=coverage.out ./...  # Coverage
go tool cover -func=coverage.out # View coverage

# Security
gosec ./...                      # Security scan
govulncheck ./...                # Vulnerability check

# Benchmarks
go test -bench=. -benchmem ./... # Performance tests
```

### Pre-commit Checklist
```bash
# Run this before every commit
gofmt -s -w . && \
go mod tidy && \
golangci-lint run && \
go test -race -short ./... && \
echo "✅ Ready to commit!"
```

## 📝 Configuration

### Adjust Coverage Threshold
Edit `.github/workflows/pr-validation.yml`:
```yaml
THRESHOLD=75  # Change to desired percentage
```

### Modify Linter Rules
Edit `.golangci.yml`:
```yaml
linters:
  enable:
    - newlinter  # Add new linters here
```

### Update Go Version
Edit `.github/workflows/pr-validation.yml`:
```yaml
go-version: '1.24'  # Update version
```

## 🐛 Troubleshooting

### Coverage Below Threshold
```bash
# See uncovered lines in browser
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Race Condition Found
```bash
# Run specific test with race detector
go test -race -v -run=TestName ./...
```

### Linter Errors
```bash
# See detailed lint errors
golangci-lint run -v

# Auto-fix some issues
golangci-lint run --fix
```

### Provider Test Fails
```bash
# Test specific provider
go test -v -run='.*Azure.*' ./internal/providers/
```

## 📈 Metrics & Monitoring

### GitHub Actions Dashboard
- View all runs: `Actions` tab
- Filter by workflow, branch, status
- Download logs and artifacts

### Status Badge
Add to README.md:
```markdown
[![PR Validation](https://github.com/lukaszraczylo/traefikoidc/actions/workflows/pr-validation.yml/badge.svg)](https://github.com/lukaszraczylo/traefikoidc/actions/workflows/pr-validation.yml)
```

### Notifications
- Configure in: Settings → Notifications
- Email alerts for workflow failures
- Slack/Discord webhooks supported

## 🔄 Continuous Improvement

### Dependabot Updates
- Automatic weekly dependency checks (Mondays 9 AM)
- Security updates prioritized
- Groups patch updates together

### Code Owners
- Auto-assigns reviewers based on file paths
- Ensures expertise reviews changes
- Speeds up PR review process

## 📚 Additional Resources

- [Workflow Documentation](.github/workflows/README.md)
- [golangci-lint Rules](.golangci.yml)
- [PR Template](.github/PULL_REQUEST_TEMPLATE.md)
- [Dependabot Config](.github/dependabot.yml)

## 🎉 Benefits

### For Contributors
- Clear expectations via PR template
- Fast feedback (5-10 min)
- Comprehensive local tooling
- Detailed error messages

### For Maintainers
- Automated code review
- Security scanning
- Performance tracking
- Quality gates enforcement

### For Users
- Higher code quality
- Fewer bugs in production
- Better security
- Consistent performance

## 🚦 Success Criteria

All PRs must pass:
- ✅ All 20+ parallel checks
- ✅ 75% test coverage minimum
- ✅ Zero security vulnerabilities
- ✅ No race conditions
- ✅ No memory leaks
- ✅ All providers tested
- ✅ Builds on all platforms

## 💡 Tips

1. **Run checks locally** before pushing to save CI time
2. **Watch for PR comments** - coverage stats posted automatically
3. **Check Security tab** for gosec/CodeQL findings
4. **Review benchmark results** in artifacts
5. **Use draft PRs** for work-in-progress to skip some checks

---

**Ready to go!** 🚀 Push your changes and create a PR to see it in action.
