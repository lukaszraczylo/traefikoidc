package backends

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionPool manages a pool of Redis connections
// Pure-Go implementation compatible with Yaegi
type ConnectionPool struct {
	config *PoolConfig

	connections chan *RedisConn
	mu          sync.Mutex
	closed      atomic.Bool

	// Metrics
	activeConns atomic.Int32
	totalConns  atomic.Int32
	gets        atomic.Int64
	puts        atomic.Int64
	timeouts    atomic.Int64
}

// PoolConfig holds connection pool configuration
type PoolConfig struct {
	Address           string
	Password          string
	DB                int
	MaxConnections    int
	ConnectTimeout    time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	EnableHealthCheck bool          // Enable connection health validation
	MaxRetries        int           // Max retries for failed operations
	RetryDelay        time.Duration // Initial delay between retries
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(config *PoolConfig) (*ConnectionPool, error) {
	if config == nil {
		return nil, errors.New("config is required")
	}

	if config.MaxConnections <= 0 {
		config.MaxConnections = 10
	}

	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 5 * time.Second
	}

	pool := &ConnectionPool{
		config:      config,
		connections: make(chan *RedisConn, config.MaxConnections),
	}

	return pool, nil
}

// Get retrieves a connection from the pool or creates a new one
func (p *ConnectionPool) Get(ctx context.Context) (*RedisConn, error) {
	if p.closed.Load() {
		return nil, ErrBackendClosed
	}

	p.gets.Add(1)

	// Try to get a connection with validation
	maxAttempts := 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var conn *RedisConn
		var err error

		select {
		case conn = <-p.connections:
			// Reuse existing connection - validate if health check enabled
			if p.config.EnableHealthCheck && !p.isConnectionHealthy(conn) {
				// Connection is stale, close it and try again
				conn.Close()
				p.totalConns.Add(-1)
				continue
			}
			p.activeConns.Add(1)
			return conn, nil

		case <-ctx.Done():
			return nil, ctx.Err()

		default:
			// No available connection, create new one if under limit
			if p.totalConns.Load() < int32(p.config.MaxConnections) {
				conn, err = p.createConnection()
				if err != nil {
					// If this is the last attempt, return error
					if attempt == maxAttempts-1 {
						return nil, err
					}
					// Wait before retry with exponential backoff
					time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
					continue
				}
				p.activeConns.Add(1)
				p.totalConns.Add(1)
				return conn, nil
			}

			// Pool exhausted, wait for a connection with timeout
			select {
			case conn = <-p.connections:
				// Validate connection if health check enabled
				if p.config.EnableHealthCheck && !p.isConnectionHealthy(conn) {
					conn.Close()
					p.totalConns.Add(-1)
					continue
				}
				p.activeConns.Add(1)
				return conn, nil
			case <-ctx.Done():
				p.timeouts.Add(1)
				return nil, ctx.Err()
			case <-time.After(p.config.ConnectTimeout):
				p.timeouts.Add(1)
				return nil, ErrPoolExhausted
			}
		}
	}

	return nil, errors.New("failed to get healthy connection after retries")
}

// Put returns a connection to the pool
func (p *ConnectionPool) Put(conn *RedisConn) {
	if conn == nil {
		return
	}

	p.puts.Add(1)
	p.activeConns.Add(-1)

	if p.closed.Load() || conn.closed.Load() {
		conn.Close()
		p.totalConns.Add(-1)
		return
	}

	// Return to pool (non-blocking)
	select {
	case p.connections <- conn:
		// Successfully returned to pool
	default:
		// Pool full, close connection
		conn.Close()
		p.totalConns.Add(-1)
	}
}

// Close closes all connections in the pool
func (p *ConnectionPool) Close() error {
	if p.closed.Swap(true) {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	close(p.connections)

	// Close all pooled connections
	for conn := range p.connections {
		conn.Close()
	}

	return nil
}

// Stats returns pool statistics
func (p *ConnectionPool) Stats() map[string]interface{} {
	return map[string]interface{}{
		"active_connections": p.activeConns.Load(),
		"total_connections":  p.totalConns.Load(),
		"max_connections":    p.config.MaxConnections,
		"gets":               p.gets.Load(),
		"puts":               p.puts.Load(),
		"timeouts":           p.timeouts.Load(),
	}
}

// createConnection creates a new Redis connection
func (p *ConnectionPool) createConnection() (*RedisConn, error) {
	// Connect with timeout
	dialer := &net.Dialer{
		Timeout: p.config.ConnectTimeout,
	}

	conn, err := dialer.Dial("tcp", p.config.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	redisConn := &RedisConn{
		conn:         conn,
		readTimeout:  p.config.ReadTimeout,
		writeTimeout: p.config.WriteTimeout,
	}

	// Authenticate if password is provided
	if p.config.Password != "" {
		if _, err := redisConn.Do("AUTH", p.config.Password); err != nil {
			redisConn.Close()
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
	}

	// Select database
	if p.config.DB != 0 {
		if _, err := redisConn.Do("SELECT", fmt.Sprintf("%d", p.config.DB)); err != nil {
			redisConn.Close()
			return nil, fmt.Errorf("failed to select database: %w", err)
		}
	}

	return redisConn, nil
}

// RedisConn represents a single Redis connection
type RedisConn struct {
	conn         net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
	closed       atomic.Bool
	mu           sync.Mutex
}

// Do executes a Redis command and returns the response
func (c *RedisConn) Do(command string, args ...string) (interface{}, error) {
	if c.closed.Load() {
		return nil, ErrBackendClosed
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Build command arguments
	// Validate total argument size to prevent memory exhaustion
	const maxTotalArgBytes = 64 << 20 // 64 MiB max total size
	totalBytes := len(command)
	for _, s := range args {
		// Protect against possible overflow
		if len(s) > maxTotalArgBytes-totalBytes {
			return nil, errors.New("arguments too large (would overflow maximum allowed total size)")
		}
		totalBytes += len(s)
		if totalBytes > maxTotalArgBytes {
			return nil, errors.New("total argument size exceeds maximum allowed")
		}
	}
	// Build command slice: prepend command to args
	// Using append avoids arithmetic on potentially large len(args)
	cmdArgs := append([]string{command}, args...)

	// Set write timeout
	if c.writeTimeout > 0 {
		c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}

	// Write command (using pooled writer for memory efficiency)
	writer := NewRESPWriter(c.conn)
	err := writer.WriteCommand(cmdArgs...)
	writer.Release() // Return to pool immediately after use
	if err != nil {
		c.closed.Store(true)
		return nil, err
	}

	// Set read timeout
	if c.readTimeout > 0 {
		c.conn.SetReadDeadline(time.Now().Add(c.readTimeout))
	}

	// Read response (using pooled reader for memory efficiency)
	reader := NewRESPReader(c.conn)
	resp, err := reader.ReadResponse()
	reader.Release() // Return to pool immediately after use
	if err != nil {
		if !errors.Is(err, ErrNilResponse) {
			c.closed.Store(true)
		}
		return nil, err
	}

	return resp, nil
}

// Close closes the connection
func (c *RedisConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

// isConnectionHealthy validates a connection is still working
func (p *ConnectionPool) isConnectionHealthy(conn *RedisConn) bool {
	if conn == nil || conn.closed.Load() {
		return false
	}

	// Set a read deadline for the ping
	if conn.conn != nil {
		conn.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		defer conn.conn.SetReadDeadline(time.Time{}) // Clear deadline
	}

	_, err := conn.Do("PING")
	return err == nil
}
