package backends

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRESPWriter_WriteCommand tests RESP command writing
func TestRESPWriter_WriteCommand(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		args     []string
	}{
		{
			name:     "Simple command",
			args:     []string{"PING"},
			expected: "*1\r\n$4\r\nPING\r\n",
		},
		{
			name:     "SET command",
			args:     []string{"SET", "key", "value"},
			expected: "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n",
		},
		{
			name:     "SETEX command",
			args:     []string{"SETEX", "mykey", "60", "myvalue"},
			expected: "*4\r\n$5\r\nSETEX\r\n$5\r\nmykey\r\n$2\r\n60\r\n$7\r\nmyvalue\r\n",
		},
		{
			name:     "DEL with multiple keys",
			args:     []string{"DEL", "key1", "key2", "key3"},
			expected: "*4\r\n$3\r\nDEL\r\n$4\r\nkey1\r\n$4\r\nkey2\r\n$4\r\nkey3\r\n",
		},
		{
			name:     "Command with empty string",
			args:     []string{"SET", "key", ""},
			expected: "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$0\r\n\r\n",
		},
		{
			name:     "Command with special characters",
			args:     []string{"SET", "key", "val\r\nue"},
			expected: "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$7\r\nval\r\nue\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			writer := NewRESPWriter(buf)

			err := writer.WriteCommand(tt.args...)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, buf.String())
		})
	}
}

// TestRESPReader_ReadSimpleString tests reading simple strings
func TestRESPReader_ReadSimpleString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "OK response",
			input:    "+OK\r\n",
			expected: "OK",
			wantErr:  false,
		},
		{
			name:     "PONG response",
			input:    "+PONG\r\n",
			expected: "PONG",
			wantErr:  false,
		},
		{
			name:     "Empty string",
			input:    "+\r\n",
			expected: "",
			wantErr:  false,
		},
		{
			name:     "String with spaces",
			input:    "+Hello World\r\n",
			expected: "Hello World",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := NewRESPReader(strings.NewReader(tt.input))
			result, err := reader.ReadResponse()

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRESPReader_ReadError tests reading error messages
func TestRESPReader_ReadError(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedError string
	}{
		{
			name:          "ERR error",
			input:         "-ERR unknown command\r\n",
			expectedError: "ERR unknown command",
		},
		{
			name:          "WRONGTYPE error",
			input:         "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n",
			expectedError: "WRONGTYPE Operation against a key holding the wrong kind of value",
		},
		{
			name:          "Simple error",
			input:         "-Error\r\n",
			expectedError: "Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := NewRESPReader(strings.NewReader(tt.input))
			_, err := reader.ReadResponse()

			require.Error(t, err)
			assert.Equal(t, tt.expectedError, err.Error())
		})
	}
}

// TestRESPReader_ReadInteger tests reading integers
func TestRESPReader_ReadInteger(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
		wantErr  bool
	}{
		{
			name:     "Zero",
			input:    ":0\r\n",
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "Positive integer",
			input:    ":1000\r\n",
			expected: 1000,
			wantErr:  false,
		},
		{
			name:     "Negative integer",
			input:    ":-1\r\n",
			expected: -1,
			wantErr:  false,
		},
		{
			name:     "Large integer",
			input:    ":9223372036854775807\r\n",
			expected: 9223372036854775807,
			wantErr:  false,
		},
		{
			name:    "Invalid integer",
			input:   ":abc\r\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := NewRESPReader(strings.NewReader(tt.input))
			result, err := reader.ReadResponse()

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRESPReader_ReadBulkString tests reading bulk strings
func TestRESPReader_ReadBulkString(t *testing.T) {
	tests := []struct {
		expected interface{}
		name     string
		input    string
		wantErr  bool
		isNil    bool
	}{
		{
			name:     "Simple bulk string",
			input:    "$6\r\nfoobar\r\n",
			expected: "foobar",
			wantErr:  false,
		},
		{
			name:     "Empty bulk string",
			input:    "$0\r\n\r\n",
			expected: "",
			wantErr:  false,
		},
		{
			name:     "Nil bulk string",
			input:    "$-1\r\n",
			expected: nil,
			wantErr:  true,
			isNil:    true,
		},
		{
			name:     "Binary safe bulk string",
			input:    "$5\r\n\x00\x01\x02\x03\x04\r\n",
			expected: "\x00\x01\x02\x03\x04",
			wantErr:  false,
		},
		{
			name:    "Invalid length",
			input:   "$abc\r\ntest\r\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := NewRESPReader(strings.NewReader(tt.input))
			result, err := reader.ReadResponse()

			if tt.isNil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrNilResponse))
				return
			}

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRESPReader_ReadArray tests reading arrays
func TestRESPReader_ReadArray(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []interface{}
		wantErr  bool
		isNil    bool
	}{
		{
			name:     "Empty array",
			input:    "*0\r\n",
			expected: []interface{}{},
			wantErr:  false,
		},
		{
			name:  "Array of bulk strings",
			input: "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n",
			expected: []interface{}{
				"foo",
				"bar",
			},
			wantErr: false,
		},
		{
			name:  "Array of integers",
			input: "*3\r\n:1\r\n:2\r\n:3\r\n",
			expected: []interface{}{
				int64(1),
				int64(2),
				int64(3),
			},
			wantErr: false,
		},
		{
			name:  "Mixed array",
			input: "*5\r\n:1\r\n:2\r\n:3\r\n:4\r\n$6\r\nfoobar\r\n",
			expected: []interface{}{
				int64(1),
				int64(2),
				int64(3),
				int64(4),
				"foobar",
			},
			wantErr: false,
		},
		{
			name:     "Nil array",
			input:    "*-1\r\n",
			expected: nil,
			wantErr:  true,
			isNil:    true,
		},
		{
			name:  "Nested arrays",
			input: "*2\r\n*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n*1\r\n$3\r\nbaz\r\n",
			expected: []interface{}{
				[]interface{}{"foo", "bar"},
				[]interface{}{"baz"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := NewRESPReader(strings.NewReader(tt.input))
			result, err := reader.ReadResponse()

			if tt.isNil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrNilResponse))
				return
			}

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRESPReader_InvalidInput tests error handling for invalid input
func TestRESPReader_InvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Unknown type byte",
			input: "?invalid\r\n",
		},
		{
			name:  "Incomplete response",
			input: "+OK",
		},
		{
			name:  "Missing CRLF in bulk string",
			input: "$5\r\nhello",
		},
		{
			name:  "Truncated array",
			input: "*3\r\n:1\r\n:2\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := NewRESPReader(strings.NewReader(tt.input))
			_, err := reader.ReadResponse()
			require.Error(t, err)
		})
	}
}

// TestRESPReader_EOF tests handling of EOF
func TestRESPReader_EOF(t *testing.T) {
	reader := NewRESPReader(strings.NewReader(""))
	_, err := reader.ReadResponse()
	require.Error(t, err)
	assert.True(t, errors.Is(err, io.EOF))
}

// TestRESPHelpers tests helper functions
func TestRESPHelpers(t *testing.T) {
	t.Run("RESPString", func(t *testing.T) {
		// Valid string
		result, err := RESPString("hello")
		require.NoError(t, err)
		assert.Equal(t, "hello", result)

		// Byte slice
		result, err = RESPString([]byte("world"))
		require.NoError(t, err)
		assert.Equal(t, "world", result)

		// Nil
		_, err = RESPString(nil)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrNilResponse))

		// Invalid type
		_, err = RESPString(123)
		require.Error(t, err)
	})

	t.Run("RESPInt", func(t *testing.T) {
		// Valid int64
		result, err := RESPInt(int64(42))
		require.NoError(t, err)
		assert.Equal(t, int64(42), result)

		// Valid int
		result, err = RESPInt(42)
		require.NoError(t, err)
		assert.Equal(t, int64(42), result)

		// Nil
		_, err = RESPInt(nil)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrNilResponse))

		// Invalid type
		_, err = RESPInt("string")
		require.Error(t, err)
	})
}

// TestRESPRoundTrip tests full round-trip encoding/decoding
func TestRESPRoundTrip(t *testing.T) {
	tests := []struct {
		expected interface{}
		name     string
		response string
		command  []string
	}{
		{
			name:     "PING command",
			command:  []string{"PING"},
			response: "+PONG\r\n",
			expected: "PONG",
		},
		{
			name:     "GET command with result",
			command:  []string{"GET", "mykey"},
			response: "$7\r\nmyvalue\r\n",
			expected: "myvalue",
		},
		{
			name:     "GET command with nil",
			command:  []string{"GET", "nonexistent"},
			response: "$-1\r\n",
			expected: nil,
		},
		{
			name:     "DEL command",
			command:  []string{"DEL", "key1", "key2"},
			response: ":2\r\n",
			expected: int64(2),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write command
			writeBuf := &bytes.Buffer{}
			writer := NewRESPWriter(writeBuf)
			err := writer.WriteCommand(tt.command...)
			require.NoError(t, err)

			// Read response
			reader := NewRESPReader(strings.NewReader(tt.response))
			result, err := reader.ReadResponse()

			if tt.expected == nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrNilResponse))
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
