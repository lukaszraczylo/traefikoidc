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
				_ = conn.Close()
				p.totalConns.Add(-1)
				continue
			}
			p.activeConns.Add(1)
			return conn, nil

		case <-ctx.Done():
			return nil, ctx.Err()

		default:
			// No available connection, create new one if under limit
			// #nosec G115 -- MaxConnections is a small config value that fits in int32
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
					_ = conn.Close()
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
		_ = conn.Close()
		p.totalConns.Add(-1)
		return
	}

	// Return to pool (non-blocking)
	select {
	case p.connections <- conn:
		// Successfully returned to pool
	default:
		// Pool full, close connection
		_ = conn.Close()
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
		_ = conn.Close()
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
			_ = redisConn.Close()
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
	}

	// Select database
	if p.config.DB != 0 {
		if _, err := redisConn.Do("SELECT", fmt.Sprintf("%d", p.config.DB)); err != nil {
			_ = redisConn.Close()
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

	// Validate argument count to prevent integer overflow in slice operations
	// maxSafeArgs is set to (1<<20)-1 = 1,048,575 which is more than any reasonable Redis command
	const maxSafeArgs = (1 << 20) - 1
	if len(args) > maxSafeArgs {
		return nil, errors.New("too many arguments: exceeds maximum safe count")
	}

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
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
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
		_ = c.conn.SetReadDeadline(time.Now().Add(c.readTimeout))
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
		_ = conn.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		defer func() { _ = conn.conn.SetReadDeadline(time.Time{}) }() // Clear deadline
	}

	_, err := conn.Do("PING")
	return err == nil
}

// Pipeline represents a Redis pipeline for batch operations
// It queues multiple commands and executes them in a single round-trip
type Pipeline struct {
	conn     *RedisConn
	commands []pipelineCommand
	mu       sync.Mutex
}

// pipelineCommand represents a single command in the pipeline
type pipelineCommand struct {
	command string
	args    []string
}

// NewPipeline creates a new pipeline for the connection
func (c *RedisConn) NewPipeline() *Pipeline {
	return &Pipeline{
		conn:     c,
		commands: make([]pipelineCommand, 0, 16), // Pre-allocate for typical batch size
	}
}

// Queue adds a command to the pipeline
func (p *Pipeline) Queue(command string, args ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.commands = append(p.commands, pipelineCommand{
		command: command,
		args:    args,
	})
}

// Execute sends all queued commands and returns all responses
// Returns a slice of responses in the same order as commands were queued
func (p *Pipeline) Execute() ([]interface{}, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.commands) == 0 {
		return nil, nil
	}

	if p.conn.closed.Load() {
		return nil, ErrBackendClosed
	}

	p.conn.mu.Lock()
	defer p.conn.mu.Unlock()

	// Set write timeout for all commands
	if p.conn.writeTimeout > 0 {
		// Use longer timeout for batch operations
		timeout := p.conn.writeTimeout * time.Duration(len(p.commands))
		if timeout > 30*time.Second {
			timeout = 30 * time.Second // Cap at 30 seconds
		}
		_ = p.conn.conn.SetWriteDeadline(time.Now().Add(timeout))
	}

	// Write all commands (pipelining - send all before reading any responses)
	writer := NewRESPWriter(p.conn.conn)
	for _, cmd := range p.commands {
		cmdArgs := append([]string{cmd.command}, cmd.args...)
		if err := writer.WriteCommand(cmdArgs...); err != nil {
			writer.Release()
			p.conn.closed.Store(true)
			return nil, fmt.Errorf("pipeline write error: %w", err)
		}
	}
	writer.Release()

	// Set read timeout for all responses
	if p.conn.readTimeout > 0 {
		timeout := p.conn.readTimeout * time.Duration(len(p.commands))
		if timeout > 30*time.Second {
			timeout = 30 * time.Second
		}
		_ = p.conn.conn.SetReadDeadline(time.Now().Add(timeout))
	}

	// Read all responses
	responses := make([]interface{}, len(p.commands))
	reader := NewRESPReader(p.conn.conn)
	defer reader.Release()

	for i := range p.commands {
		resp, err := reader.ReadResponse()
		if err != nil {
			// For nil responses, store nil instead of erroring
			if errors.Is(err, ErrNilResponse) {
				responses[i] = nil
				continue
			}
			p.conn.closed.Store(true)
			return responses[:i], fmt.Errorf("pipeline read error at command %d: %w", i, err)
		}
		responses[i] = resp
	}

	return responses, nil
}

// Clear resets the pipeline for reuse
func (p *Pipeline) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.commands = p.commands[:0]
}

// Len returns the number of queued commands
func (p *Pipeline) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.commands)
}
