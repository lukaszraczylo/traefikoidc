# Test Execution Guide

This guide explains how to run tests efficiently with the new test categorization and optimization system.

## Quick Start

### Fast Development Testing (Default - Target: < 30 seconds)
```bash
# Run quick smoke tests only
go test ./... 

# Or explicitly run in short mode
go test ./... -short
```

### Extended Testing (Target: 2-5 minutes)
```bash
# Enable extended tests with more iterations and concurrency
RUN_EXTENDED_TESTS=1 go test ./...

# Or use the flag equivalent (if using test runner that supports it)
go test ./... -extended
```

### Long-Running Performance Tests (Target: 5-15 minutes)
```bash
# Enable comprehensive performance and stress tests
RUN_LONG_TESTS=1 go test ./...
```

### Full Stress Testing (Target: 10-30 minutes)
```bash
# Enable all stress tests with maximum parameters
RUN_STRESS_TESTS=1 go test ./...
```

## Test Categories

### 1. Quick Tests (Default)
- **Purpose**: Fast feedback during development
- **Duration**: < 30 seconds total
- **Features**:
  - Basic functionality verification
  - Limited iterations (1-3)
  - Small data sets
  - Minimal concurrency
  - Essential memory leak checks

**Configuration**:
- Max Iterations: 3
- Max Concurrency: 5
- Memory Threshold: 2.0 MB
- Cache Size: 50
- Timeout: 10 seconds

### 2. Extended Tests
- **Purpose**: Comprehensive testing before commits
- **Duration**: 2-5 minutes
- **Features**:
  - Increased test coverage
  - More iterations (5-10)
  - Medium concurrency tests
  - Enhanced memory leak detection

**Configuration**:
- Max Iterations: 10
- Max Concurrency: 20
- Memory Threshold: 10.0 MB
- Cache Size: 200
- Timeout: 30 seconds

### 3. Long Tests
- **Purpose**: Performance validation and stress testing
- **Duration**: 5-15 minutes
- **Features**:
  - High iteration counts (50-100)
  - High concurrency scenarios
  - Large data sets
  - Comprehensive memory testing

**Configuration**:
- Max Iterations: 100
- Max Concurrency: 50
- Memory Threshold: 50.0 MB
- Cache Size: 1000
- Timeout: 60 seconds

### 4. Stress Tests
- **Purpose**: Maximum load testing and edge case validation
- **Duration**: 10-30 minutes
- **Features**:
  - Extreme iteration counts (100-500)
  - Maximum concurrency (100+)
  - Large memory allocations
  - Edge case combinations

**Configuration**:
- Max Iterations: 500
- Max Concurrency: 100
- Memory Threshold: 100.0 MB
- Cache Size: 2000
- Timeout: 120 seconds

## Environment Variables

### Test Execution Control
```bash
# Enable specific test types
export RUN_EXTENDED_TESTS=1        # Enable extended tests
export RUN_LONG_TESTS=1           # Enable long-running tests
export RUN_STRESS_TESTS=1         # Enable stress tests

# Disable specific features
export DISABLE_LEAK_DETECTION=1   # Skip memory leak detection
```

### Parameter Customization
```bash
# Customize concurrency limits
export TEST_MAX_CONCURRENCY=10    # Override max concurrent operations

# Customize iteration limits
export TEST_MAX_ITERATIONS=50     # Override max test iterations

# Customize memory thresholds
export TEST_MEMORY_THRESHOLD_MB=25.5  # Override memory growth limit (in MB)
```

## Test-Specific Behavior

### Memory Leak Tests
- **Quick Mode**: 1-3 iterations, small data sets, strict memory limits
- **Extended Mode**: 5-10 iterations, medium data sets, relaxed limits
- **Long Mode**: 50-100 iterations, large data sets, performance focus
- **Stress Mode**: 100-500 iterations, maximum data sets, stress focus

### Concurrency Tests
- **Quick Mode**: 2-5 concurrent operations, basic race detection
- **Extended Mode**: 10-20 concurrent operations, moderate stress
- **Long Mode**: 20-50 concurrent operations, high contention
- **Stress Mode**: 50-100+ concurrent operations, maximum stress

### Cache Tests
- **Quick Mode**: Small caches (50 items), basic operations
- **Extended Mode**: Medium caches (200 items), varied operations
- **Long Mode**: Large caches (1000 items), performance testing
- **Stress Mode**: Very large caches (2000+ items), stress testing

## Integration with CI/CD

### GitHub Actions Example
```yaml
# Quick tests for every push/PR
- name: Quick Tests
  run: go test ./... -short

# Extended tests for main branch
- name: Extended Tests
  if: github.ref == 'refs/heads/main'
  run: RUN_EXTENDED_TESTS=1 go test ./...

# Nightly comprehensive testing
- name: Nightly Stress Tests
  if: github.event_name == 'schedule'
  run: RUN_STRESS_TESTS=1 go test ./...
```

### Local Development Workflow
```bash
# During active development
go test ./... -short

# Before committing
RUN_EXTENDED_TESTS=1 go test ./...

# Before major releases
RUN_LONG_TESTS=1 go test ./...

# Performance validation
RUN_STRESS_TESTS=1 go test ./...
```

## Performance Optimization Features

### Dynamic Test Scaling
The test system automatically adjusts parameters based on:
- Test mode (quick/extended/long/stress)
- Available resources
- Environment variables
- Previous test performance

### Memory Management
- **Garbage Collection**: Forced GC between test iterations
- **Memory Monitoring**: Real-time memory growth tracking
- **Leak Detection**: Goroutine and memory leak prevention
- **Resource Cleanup**: Automatic cleanup of test resources

### Timeout Management
- **Adaptive Timeouts**: Timeouts scale with test complexity
- **Graceful Degradation**: Tests adapt to slower environments
- **Early Termination**: Failed tests terminate quickly

## Troubleshooting

### Tests Taking Too Long
```bash
# Check if running in extended mode accidentally
echo $RUN_EXTENDED_TESTS $RUN_LONG_TESTS

# Force quick mode
unset RUN_EXTENDED_TESTS RUN_LONG_TESTS RUN_STRESS_TESTS
go test ./... -short
```

### Memory Issues
```bash
# Reduce memory limits for constrained environments
export TEST_MEMORY_THRESHOLD_MB=5.0
export TEST_MAX_CONCURRENCY=2
go test ./...
```

### Concurrency Issues
```bash
# Reduce concurrency for slower systems
export TEST_MAX_CONCURRENCY=5
export TEST_MAX_ITERATIONS=10
go test ./...
```

### Skip Specific Test Types
```bash
# Skip memory leak detection if problematic
export DISABLE_LEAK_DETECTION=1
go test ./...
```

## Benchmarking

### Running Benchmarks
```bash
# Quick benchmarks
go test -bench=. -short

# Extended benchmarks
RUN_EXTENDED_TESTS=1 go test -bench=.

# Memory profiling
go test -bench=. -memprofile=mem.prof
go tool pprof mem.prof
```

### Benchmark Categories
- **Basic Operations**: Set/Get performance
- **Concurrency**: Multi-threaded performance
- **Memory**: Allocation and cleanup performance
- **Cache**: Eviction and cleanup performance

## Best Practices

### For Developers
1. Always run quick tests during development (`go test ./... -short`)
2. Run extended tests before committing (`RUN_EXTENDED_TESTS=1 go test ./...`)
3. Use appropriate test categories for your use case
4. Monitor test execution time and adjust if needed

### For CI/CD
1. Use quick tests for fast feedback on PRs
2. Use extended tests for main branch validation
3. Use long tests for release validation
4. Use stress tests for nightly/weekly validation

### For Performance Testing
1. Use consistent environment variables
2. Run tests multiple times for statistical significance
3. Monitor both execution time and resource usage
4. Use profiling tools for detailed analysis

## Examples

### Daily Development
```bash
# Fast tests while coding
go test ./... -short

# Before git commit
RUN_EXTENDED_TESTS=1 go test ./...
```

### Release Testing
```bash
# Comprehensive validation
RUN_LONG_TESTS=1 go test ./...

# Stress testing
RUN_STRESS_TESTS=1 go test ./...
```

### Custom Configuration
```bash
# Custom limits for specific environment
export TEST_MAX_CONCURRENCY=8
export TEST_MAX_ITERATIONS=25
export TEST_MEMORY_THRESHOLD_MB=15.0
RUN_EXTENDED_TESTS=1 go test ./...
```

This test system provides flexible, scalable test execution that adapts to your development workflow and infrastructure constraints while maintaining comprehensive test coverage.