package backends

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// RESP (REdis Serialization Protocol) implementation
// Pure Go implementation compatible with Yaegi interpreter (no unsafe package)
//
// NOTE: sync.Pool was intentionally removed for Yaegi compatibility.
// Yaegi (Traefik's Go interpreter) has issues with sync.Pool and reflection
// that cause "reflect: call of reflect.Value.Field on zero Value" panics.
// See: https://github.com/lukaszraczylo/traefikoidc/issues/120

var (
	ErrInvalidRESP = errors.New("invalid RESP response")
	ErrNilResponse = errors.New("nil response")
)

// RESPWriter writes RESP protocol messages
type RESPWriter struct {
	w io.Writer
}

// NewRESPWriter creates a new RESP writer
func NewRESPWriter(w io.Writer) *RESPWriter {
	return &RESPWriter{w: w}
}

// Release is a no-op for API compatibility (pooling removed for Yaegi compatibility)
func (w *RESPWriter) Release() {
	// No-op: pooling removed for Yaegi compatibility
}

// WriteCommand writes a Redis command in RESP array format
// Example: SET key value EX 3600 -> *5\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n$2\r\nEX\r\n$4\r\n3600\r\n
func (w *RESPWriter) WriteCommand(args ...string) error {
	// Write array header
	if _, err := fmt.Fprintf(w.w, "*%d\r\n", len(args)); err != nil {
		return err
	}

	// Write each argument as bulk string
	for _, arg := range args {
		if _, err := fmt.Fprintf(w.w, "$%d\r\n%s\r\n", len(arg), arg); err != nil {
			return err
		}
	}

	return nil
}

// RESPReader reads RESP protocol messages
type RESPReader struct {
	r *bufio.Reader
}

// NewRESPReader creates a new RESP reader
func NewRESPReader(r io.Reader) *RESPReader {
	return &RESPReader{
		r: bufio.NewReaderSize(r, 4096),
	}
}

// Release is a no-op for API compatibility (pooling removed for Yaegi compatibility)
func (r *RESPReader) Release() {
	// No-op: pooling removed for Yaegi compatibility
}

// ReadResponse reads a RESP response and returns the parsed value
func (r *RESPReader) ReadResponse() (interface{}, error) {
	typeByte, err := r.r.ReadByte()
	if err != nil {
		return nil, err
	}

	switch typeByte {
	case '+': // Simple string
		return r.readSimpleString()
	case '-': // Error
		return nil, r.readError()
	case ':': // Integer
		return r.readInteger()
	case '$': // Bulk string
		return r.readBulkString()
	case '*': // Array
		return r.readArray()
	default:
		return nil, fmt.Errorf("%w: unknown type byte '%c'", ErrInvalidRESP, typeByte)
	}
}

// readSimpleString reads a simple string (+OK\r\n)
func (r *RESPReader) readSimpleString() (string, error) {
	line, err := r.readLine()
	if err != nil {
		return "", err
	}
	return line, nil
}

// readError reads an error message (-Error message\r\n)
func (r *RESPReader) readError() error {
	line, err := r.readLine()
	if err != nil {
		return err
	}
	return errors.New(line)
}

// readInteger reads an integer (:1000\r\n)
func (r *RESPReader) readInteger() (int64, error) {
	line, err := r.readLine()
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(line, 10, 64)
}

// readBulkString reads a bulk string ($6\r\nfoobar\r\n or $-1\r\n for nil)
func (r *RESPReader) readBulkString() (interface{}, error) {
	line, err := r.readLine()
	if err != nil {
		return nil, err
	}

	length, err := strconv.Atoi(line)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid bulk string length", ErrInvalidRESP)
	}

	// -1 indicates nil bulk string
	if length == -1 {
		return nil, ErrNilResponse
	}

	// Read exactly 'length' bytes plus \r\n
	buf := make([]byte, length+2)
	if _, err := io.ReadFull(r.r, buf); err != nil {
		return nil, err
	}

	// Verify \r\n terminator
	if buf[length] != '\r' || buf[length+1] != '\n' {
		return nil, fmt.Errorf("%w: missing CRLF after bulk string", ErrInvalidRESP)
	}

	return string(buf[:length]), nil
}

// readArray reads an array (*2\r\n...\r\n or *-1\r\n for nil)
func (r *RESPReader) readArray() (interface{}, error) {
	line, err := r.readLine()
	if err != nil {
		return nil, err
	}

	length, err := strconv.Atoi(line)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid array length", ErrInvalidRESP)
	}

	// -1 indicates nil array
	if length == -1 {
		return nil, ErrNilResponse
	}

	// Read each element
	result := make([]interface{}, length)
	for i := 0; i < length; i++ {
		elem, err := r.ReadResponse()
		if err != nil {
			return nil, err
		}
		result[i] = elem
	}

	return result, nil
}

// readLine reads a line terminated by \r\n
func (r *RESPReader) readLine() (string, error) {
	line, err := r.r.ReadString('\n')
	if err != nil {
		return "", err
	}

	// Remove \r\n
	line = strings.TrimSuffix(line, "\r\n")
	if !strings.HasSuffix(line+"\r\n", "\r\n") {
		return "", fmt.Errorf("%w: missing CRLF", ErrInvalidRESP)
	}

	return line, nil
}

// RESPString extracts a string from RESP response
func RESPString(resp interface{}) (string, error) {
	if resp == nil {
		return "", ErrNilResponse
	}

	switch v := resp.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	default:
		return "", fmt.Errorf("expected string, got %T", resp)
	}
}

// RESPInt extracts an integer from RESP response
func RESPInt(resp interface{}) (int64, error) {
	if resp == nil {
		return 0, ErrNilResponse
	}

	switch v := resp.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("expected integer, got %T", resp)
	}
}
