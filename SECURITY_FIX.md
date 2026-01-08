# Security Fix: Integer Overflow Protection in Cache Serialization

## Summary

Fixed **High severity** integer overflow vulnerability identified by GitHub Advanced Security in PR #117.

## Vulnerability

**Locations**: `universal_cache.go` lines 789 and 811
- `result := make([]byte, len(bytes)+1)` - Raw bytes path
- `result := make([]byte, len(jsonData)+1)` - JSON encoding path

**Risk**: Potential integer overflow when allocating memory for very large cache entries.

## Fix Applied

1. **Added size limit constant**:
   ```go
   maxCacheEntrySize = 64 * 1024 * 1024 // 64 MiB
   ```

2. **Size validation before allocation**:
   - Validates entry size doesn't exceed limit
   - Validates adding marker byte won't overflow
   - Returns descriptive error messages

3. **Comprehensive test coverage**:
   - Oversized byte slices (>64 MiB)
   - Exact max size edge case
   - Safe sizes (normal operation)
   - Large JSON data structures

## Verification

✅ All tests pass with race detection
✅ No security issues (golangci-lint, gosec)
✅ 76.3% test coverage maintained

## Impact

- No breaking changes
- Negligible performance overhead
- Prevents potential buffer overflows
- Predictable memory usage

---

**Date**: January 8, 2026
**Severity**: High → Resolved
