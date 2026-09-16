package backends

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRESPReader_ReadArray_NestedCommandErrorDrainsAllElements is a
// regression test for the review finding that a nested "-ERR" reply inside
// an array left the trailing array elements unread on the connection. A
// nested command-error reply is a valid protocol value (the connection
// stays healthy, see ErrCommandReply), so readArray must keep reading past
// it instead of aborting the whole array read. Failing to drain the
// trailing elements leaves them on the stream, where the next command's
// reader would pick them up as its own reply (response desync).
func TestRESPReader_ReadArray_NestedCommandErrorDrainsAllElements(t *testing.T) {
	// *3: bulk "foo", a nested command-error reply, bulk "bar" - followed
	// immediately by an independent "+PONG" reply on the same stream, as
	// the next command's response would be.
	input := "*3\r\n$3\r\nfoo\r\n-ERR boom\r\n$3\r\nbar\r\n+PONG\r\n"
	reader := NewRESPReader(strings.NewReader(input))

	result, err := reader.ReadResponse()
	require.NoError(t, err, "a nested command-error reply must not fail the whole array read")

	arr, ok := result.([]interface{})
	require.True(t, ok, "expected an array result, got %T", result)
	require.Len(t, arr, 3, "all three array elements must be present, including the one after the nested error")

	assert.Equal(t, "foo", arr[0])

	elemErr, ok := arr[1].(error)
	require.True(t, ok, "the nested error element must be stored as an error value, got %T", arr[1])
	assert.True(t, errors.Is(elemErr, ErrCommandReply), "want ErrCommandReply, got %v", elemErr)

	assert.Equal(t, "bar", arr[2], "the element after the nested error must still be read off the wire")

	// The reader must be positioned exactly at the start of the next reply,
	// not partway through leftover array bytes.
	next, err := reader.ReadResponse()
	require.NoError(t, err, "the connection must not be desynced by the nested error")
	assert.Equal(t, "PONG", next, "next command's reply must not be corrupted by unread array elements")
}

// TestRESPReader_ReadArray_NestedIOErrorStillAborts ensures a genuine
// IO/parse error nested inside an array (as opposed to a valid "-ERR"
// command-error reply) still aborts the array read, since the connection is
// no longer trustworthy in that case.
func TestRESPReader_ReadArray_NestedIOErrorStillAborts(t *testing.T) {
	// Second element is a truncated bulk string (declares 5 bytes, supplies
	// none) - a protocol/IO error, not a command-error reply.
	input := "*2\r\n$3\r\nfoo\r\n$5\r\n"
	reader := NewRESPReader(strings.NewReader(input))

	_, err := reader.ReadResponse()
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrCommandReply), "a truncated bulk string is an IO error, not a command-error reply")
}

// TestRESPReader_ReadArray_NestedNilBulkStringDrainsAllElements is a
// regression test for the same desync as the nested command-error case,
// triggered by a nested "$-1" (nil bulk string) element instead of a
// "-ERR" reply. readBulkString returns ErrNilResponse for "$-1", which is
// not an IO or protocol error and does not make the connection
// untrustworthy (see RedisConn.Do, which keeps the connection pooled on
// ErrNilResponse). readArray must store nil for that element and keep
// reading the rest of the array.
func TestRESPReader_ReadArray_NestedNilBulkStringDrainsAllElements(t *testing.T) {
	// *3: bulk "foo", a nested nil bulk string, bulk "bar" - followed
	// immediately by an independent "+PONG" reply on the same stream, as
	// the next command's response would be.
	input := "*3\r\n$3\r\nfoo\r\n$-1\r\n$3\r\nbar\r\n+PONG\r\n"
	reader := NewRESPReader(strings.NewReader(input))

	result, err := reader.ReadResponse()
	require.NoError(t, err, "a nested nil bulk string must not fail the whole array read")

	arr, ok := result.([]interface{})
	require.True(t, ok, "expected an array result, got %T", result)
	require.Len(t, arr, 3, "all three array elements must be present, including the one after the nested nil")

	assert.Equal(t, "foo", arr[0])
	assert.Nil(t, arr[1], "the nested nil bulk string must be stored as a nil element")
	assert.Equal(t, "bar", arr[2], "the element after the nested nil must still be read off the wire")

	// The reader must be positioned exactly at the start of the next reply,
	// not partway through leftover array bytes.
	next, err := reader.ReadResponse()
	require.NoError(t, err, "the connection must not be desynced by the nested nil bulk string")
	assert.Equal(t, "PONG", next, "next command's reply must not be corrupted by unread array elements")
}

// TestRESPReader_ReadArray_NestedNilArrayDrainsAllElements is the same
// regression as above for a nested "*-1" (nil array) element.
func TestRESPReader_ReadArray_NestedNilArrayDrainsAllElements(t *testing.T) {
	// *3: bulk "foo", a nested nil array, bulk "bar" - followed immediately
	// by an independent "+PONG" reply on the same stream, as the next
	// command's response would be.
	input := "*3\r\n$3\r\nfoo\r\n*-1\r\n$3\r\nbar\r\n+PONG\r\n"
	reader := NewRESPReader(strings.NewReader(input))

	result, err := reader.ReadResponse()
	require.NoError(t, err, "a nested nil array must not fail the whole array read")

	arr, ok := result.([]interface{})
	require.True(t, ok, "expected an array result, got %T", result)
	require.Len(t, arr, 3, "all three array elements must be present, including the one after the nested nil")

	assert.Equal(t, "foo", arr[0])
	assert.Nil(t, arr[1], "the nested nil array must be stored as a nil element")
	assert.Equal(t, "bar", arr[2], "the element after the nested nil must still be read off the wire")

	// The reader must be positioned exactly at the start of the next reply,
	// not partway through leftover array bytes.
	next, err := reader.ReadResponse()
	require.NoError(t, err, "the connection must not be desynced by the nested nil array")
	assert.Equal(t, "PONG", next, "next command's reply must not be corrupted by unread array elements")
}

// TestRESPReader_ReadArray_TopLevelNilBulkStringStillErrors ensures the
// top-level "$-1" contract is unchanged: only a nested nil is absorbed as
// an element, a top-level nil bulk string still returns ErrNilResponse.
func TestRESPReader_ReadArray_TopLevelNilBulkStringStillErrors(t *testing.T) {
	reader := NewRESPReader(strings.NewReader("$-1\r\n"))
	_, err := reader.ReadResponse()
	assert.True(t, errors.Is(err, ErrNilResponse), "want ErrNilResponse, got %v", err)
}

// TestRESPReader_ReadArray_TopLevelNilArrayStillErrors ensures the
// top-level "*-1" contract is unchanged: only a nested nil is absorbed as
// an element, a top-level nil array still returns ErrNilResponse.
func TestRESPReader_ReadArray_TopLevelNilArrayStillErrors(t *testing.T) {
	reader := NewRESPReader(strings.NewReader("*-1\r\n"))
	_, err := reader.ReadResponse()
	assert.True(t, errors.Is(err, ErrNilResponse), "want ErrNilResponse, got %v", err)
}
