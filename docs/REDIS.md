# Redis Cache for Distributed Deployments

Redis cache support for multi-replica Traefik deployments with shared state.

## Table of Contents

- [Overview](#overview)
- [Why Use Redis Cache?](#why-use-redis-cache)
- [Configuration](#configuration)
- [Cache Modes](#cache-modes)
- [Deployment Examples](#deployment-examples)
- [Performance Tuning](#performance-tuning)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Migration Guide](#migration-guide)

---

## Overview

The Redis cache feature provides distributed caching for the Traefik OIDC plugin, enabling seamless operation across multiple Traefik instances.

### Key Features

- **Distributed JTI Replay Detection**: Prevents token replay attacks across all instances
- **Shared Session Management**: Consistent user sessions across replicas
- **Circuit Breaker**: Automatic fallback to memory cache during Redis outages
- **Health Checking**: Continuous monitoring of Redis connectivity
- **Flexible Cache Modes**: Memory, Redis, or hybrid caching strategies
- **Pure-Go Implementation**: Yaegi-compatible, works with dynamic plugin loading

### Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Traefik #1  │     │  Traefik #2  │     │  Traefik #3  │
│   (Plugin)   │     │   (Plugin)   │     │   (Plugin)   │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       └────────────────────┼────────────────────┘
                           │
                    ┌──────▼──────┐
                    │    Redis    │
                    │   (Shared   │
                    │    Cache)   │
                    └─────────────┘
```

---

## Why Use Redis Cache?

### The Problem

When running multiple Traefik instances without shared cache:

1. **False Positive Replay Detection**
   - User authenticates → Token stored in Instance A's JTI cache
   - Next request → Load balancer routes to Instance B
   - Instance B doesn't have the JTI → Falsely detects replay attack

2. **Session Inconsistency**
   - User session created on Instance A
   - Subsequent request routed to Instance B
   - Instance B has no knowledge of the session

3. **Token Metadata Fragmentation**
   - Token refresh happens on Instance A
   - Other instances continue using old tokens

### The Solution

Redis provides centralized cache that all instances share, ensuring:

- **Consistent Authentication**: All instances share authentication state
- **True Replay Detection**: JTI cache shared across all instances
- **Seamless Scaling**: Add/remove instances without affecting sessions
- **High Availability**: Circuit breaker with automatic fallback

---

## Configuration

### Basic Configuration

```yaml
redis:
  enabled: true
  address: "redis:6379"
  password: "your-password"  # Optional
  db: 0
  keyPrefix: "traefikoidc:"
  cacheMode: "hybrid"
```

### All Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | bool | `false` | Enable Redis caching |
| `address` | string | - | Redis server address (`host:port`) |
| `password` | string | - | Redis password (optional) |
| `db` | int | `0` | Redis database number (0-15) |
| `keyPrefix` | string | `traefikoidc:` | Prefix for all Redis keys |
| `cacheMode` | string | `redis` | Cache mode: `memory`, `redis`, `hybrid` |
| `poolSize` | int | `10` | Connection pool size |
| `connectTimeout` | int | `5` | Connection timeout (seconds) |
| `readTimeout` | int | `3` | Read timeout (seconds) |
| `writeTimeout` | int | `3` | Write timeout (seconds) |
| `enableTLS` | bool | `false` | Enable TLS for connections |
| `tlsSkipVerify` | bool | `false` | Skip TLS certificate verification |
| `enableCircuitBreaker` | bool | `true` | Enable circuit breaker |
| `circuitBreakerThreshold` | int | `5` | Failures before circuit opens |
| `circuitBreakerTimeout` | int | `60` | Circuit reset timeout (seconds) |
| `enableHealthCheck` | bool | `true` | Enable periodic health checks |
| `healthCheckInterval` | int | `30` | Health check interval (seconds) |
| `hybridL1Size` | int | `500` | Max items in L1 cache (hybrid mode) |
| `hybridL1MemoryMB` | int64 | `10` | Max memory for L1 cache in MB |

### Environment Variables (Fallback)

If not configured through Traefik, these environment variables are used:

```bash
REDIS_ENABLED=true
REDIS_ADDRESS=redis:6379
REDIS_PASSWORD=your-password
REDIS_DB=0
REDIS_KEY_PREFIX=traefikoidc:
REDIS_CACHE_MODE=hybrid
REDIS_POOL_SIZE=10
REDIS_CONNECT_TIMEOUT=5
REDIS_READ_TIMEOUT=3
REDIS_WRITE_TIMEOUT=3
REDIS_ENABLE_TLS=false
REDIS_TLS_SKIP_VERIFY=false
```

---

## Cache Modes

### Memory Mode (Default without Redis)

```yaml
redis:
  cacheMode: "memory"
```

- Uses only in-memory cache
- Suitable for single-instance deployments
- No Redis dependency
- Fastest performance

### Redis Mode

```yaml
redis:
  enabled: true
  address: "redis:6379"
  cacheMode: "redis"
```

- All operations go directly to Redis
- Ensures consistency across replicas
- Slightly higher latency

### Hybrid Mode (Recommended)

```yaml
redis:
  enabled: true
  address: "redis:6379"
  cacheMode: "hybrid"
```

Two-tier caching strategy:

```
┌─────────────────────────────────────────┐
│            Client Request               │
└────────────────┬────────────────────────┘
                 ▼
        ┌────────────────┐
        │  Local Cache   │ ← L1 Cache (Fast)
        │   (Memory)     │
        └────────┬───────┘
                 │ Miss
                 ▼
        ┌────────────────┐
        │  Remote Cache  │ ← L2 Cache (Shared)
        │    (Redis)     │
        └────────────────┘
```

**Read Path:**
1. Check local memory cache (L1)
2. On miss, check Redis (L2)
3. On hit in Redis, populate L1
4. Return value

**Write Path:**
1. Write to Redis (L2) for durability
2. Write to local cache (L1) for speed

### Performance Comparison

| Operation | Memory Mode | Redis Mode | Hybrid Mode |
|-----------|------------|------------|-------------|
| Read (p50) | 0.1ms | 2ms | 0.2ms |
| Read (p99) | 0.5ms | 10ms | 5ms |
| Write (p50) | 0.2ms | 3ms | 3ms |
| Throughput | 100k/s | 20k/s | 80k/s |

---

## Deployment Examples

### Docker Compose

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 30s
      timeout: 3s
      retries: 3

  traefik:
    image: traefik:v3.2
    deploy:
      replicas: 3
    labels:
      - "traefik.http.middlewares.oidc.plugin.traefikoidc.redis.enabled=true"
      - "traefik.http.middlewares.oidc.plugin.traefikoidc.redis.address=redis:6379"
      - "traefik.http.middlewares.oidc.plugin.traefikoidc.redis.password=${REDIS_PASSWORD}"
      - "traefik.http.middlewares.oidc.plugin.traefikoidc.redis.cacheMode=hybrid"
    depends_on:
      redis:
        condition: service_healthy

volumes:
  redis-data:
```

### Kubernetes

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: oidc-with-redis
spec:
  plugin:
    traefikoidc:
      providerURL: https://accounts.google.com
      clientID: your-client-id
      clientSecret: your-client-secret
      sessionEncryptionKey: your-encryption-key
      callbackURL: /oauth2/callback
      redis:
        enabled: true
        address: "redis-service.redis-namespace:6379"
        password: "urn:k8s:secret:redis-secret:password"
        db: 0
        keyPrefix: "traefikoidc:"
        cacheMode: "hybrid"
        poolSize: 20
        enableCircuitBreaker: true
        circuitBreakerThreshold: 5
```

### AWS ElastiCache

```yaml
redis:
  enabled: true
  address: "your-cache.abc123.cache.amazonaws.com:6379"
  cacheMode: "hybrid"
  enableTLS: true
  password: "your-elasticache-auth-token"
```

---

## Performance Tuning

### Connection Pool Sizing

```yaml
redis:
  poolSize: 20        # Formula: 2 * CPU cores * replicas
  # For 4 cores, 3 replicas: poolSize = 24
```

### TTL Strategy

The plugin automatically sets TTLs based on token lifetimes:

- **JTI Cache**: Matches token lifetime (typically 1 hour)
- **Session**: Matches `sessionMaxAge` configuration
- **Token Metadata**: 5 minutes (short-lived)

### Redis Server Configuration

```bash
# Recommended Redis settings for cache
maxmemory 512mb
maxmemory-policy allkeys-lru  # Evict least recently used

# For cache data, disable persistence for better performance
save ""
appendonly no
```

### Hybrid Mode Tuning

```yaml
redis:
  cacheMode: "hybrid"
  hybridL1Size: 500      # Max items in local cache
  hybridL1MemoryMB: 10   # Max memory for local cache
```

---

## Monitoring

### Key Metrics

- **Cache hit rate** (target: >90% for hybrid mode)
- **Redis latency** (target: <10ms p99)
- **Circuit breaker state**
- **Connection pool utilization

### Redis Commands for Monitoring

```bash
# Monitor commands in real-time
redis-cli MONITOR

# Check slow queries
redis-cli SLOWLOG GET 10

# Memory usage
redis-cli INFO memory

# Key statistics
redis-cli DBSIZE

# List keys with prefix
redis-cli --scan --pattern "traefikoidc:*"

# Check key TTL
redis-cli TTL "traefikoidc:session:abc123"
```

### Health Check Endpoint

The plugin provides health information including:

```json
{
  "status": "healthy",
  "cache": {
    "mode": "hybrid",
    "redis": {
      "connected": true,
      "latency": "2ms"
    },
    "circuit_breaker": {
      "state": "closed",
      "failures": 0
    }
  }
}
```

---

## Troubleshooting

### Connection Refused

**Symptoms:** `dial tcp: connection refused`

**Solutions:**
1. Verify Redis is running: `redis-cli ping`
2. Check network connectivity: `telnet redis-host 6379`
3. Verify address configuration

### Authentication Failure

**Symptoms:** `NOAUTH Authentication required`

**Solutions:**
1. Set Redis password in configuration
2. Verify password is correct

### Circuit Breaker Open

**Symptoms:** `Circuit breaker is open`, falling back to memory

**Solutions:**
1. Check Redis health: `redis-cli INFO server`
2. Review network latency: `redis-cli --latency`
3. Adjust circuit breaker thresholds if needed

### High Memory Usage

**Symptoms:** Redis memory constantly growing, OOM errors

**Solutions:**
1. Configure eviction policy:
   ```bash
   CONFIG SET maxmemory 512mb
   CONFIG SET maxmemory-policy allkeys-lru
   ```
2. Review key count: `redis-cli DBSIZE`
3. Check for large keys: `redis-cli --bigkeys`

### Inconsistent Cache State

**Symptoms:** Different responses from different replicas

**Solutions:**
1. Verify all instances use the same Redis address
2. Check cache mode consistency across instances
3. Verify time synchronization on all hosts

---

## Migration Guide

### From Memory-Only to Redis

#### Phase 1: Preparation

1. Deploy Redis infrastructure
2. Test Redis connectivity
3. Configure monitoring

#### Phase 2: Gradual Rollout

1. Enable Redis on one instance:
   ```yaml
   redis:
     enabled: true
     address: "redis:6379"
     cacheMode: "hybrid"
   ```
2. Monitor for errors
3. Gradually enable on more instances

#### Phase 3: Full Migration

1. Enable Redis on all instances
2. Remove `disableReplayDetection: true` if set
3. Monitor for issues

### Rollback Plan

If issues occur:
1. Set `redis.enabled: false`
2. Plugin falls back to memory cache automatically
3. Investigate and resolve issues

### Migration Checklist

- [ ] Redis deployed and accessible
- [ ] Redis password configured
- [ ] Network connectivity verified
- [ ] Monitoring configured
- [ ] Backup plan prepared
- [ ] Test environment validated
- [ ] Gradual rollout planned

---

## Best Practices

### Security

- Always use Redis password authentication
- Enable TLS for production deployments
- Use network segmentation (private subnets)
- Rotate Redis passwords regularly

### High Availability

- Use Redis Sentinel or Cluster for HA
- Configure appropriate circuit breaker thresholds
- Implement proper health checks
- Use connection pooling

### Performance

- Use hybrid cache mode for best performance
- Monitor cache hit rates
- Size Redis memory appropriately
- Disable persistence for cache-only usage

### Operations

- Implement comprehensive monitoring
- Set up alerting for circuit breaker state
- Document Redis configuration
- Test failover scenarios

---

## FAQ

### Is Redis required?

No, Redis is optional. The plugin works with in-memory cache for single-instance deployments.

### What happens if Redis goes down?

The circuit breaker opens after threshold failures, and the plugin falls back to in-memory cache. It periodically attempts to reconnect.

### Which cache mode should I use?

For production multi-replica deployments, use `hybrid` mode for best performance and consistency.

### How much memory does Redis need?

Depends on active sessions and token sizes:
- Small (1-1000 users): 128MB
- Medium (1000-10000 users): 256-512MB
- Large (10000+ users): 1GB+

### Can I use managed Redis services?

Yes, the plugin works with AWS ElastiCache, Azure Cache for Redis, Google Cloud Memorystore, and Redis Enterprise Cloud.

### Is data encrypted in Redis?

Session data is encrypted before storing using `sessionEncryptionKey`. Additionally, you can enable TLS for Redis connections.
