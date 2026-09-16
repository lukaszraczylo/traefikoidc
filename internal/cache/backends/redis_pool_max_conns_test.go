package backends

import (
	"math"
	"strconv"
	"testing"
)

// TestReserveConnectionSlotLargeMaxConnections pins the gosec G115 fix: the
// limit was narrowed with int32(MaxConnections), so a value above MaxInt32
// wrapped to a negative limit and every connection was refused.
func TestReserveConnectionSlotLargeMaxConnections(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("int cannot exceed MaxInt32 on this platform")
	}
	p := &ConnectionPool{config: &PoolConfig{MaxConnections: math.MaxInt32 + 1}}
	if !p.reserveConnectionSlot() {
		t.Fatal("reserveConnectionSlot refused a connection although MaxConnections is far above the current count")
	}
	if got := p.totalConns.Load(); got != 1 {
		t.Fatalf("totalConns = %d, want 1", got)
	}
}

// TestReserveConnectionSlotRespectsLimit checks that the int64 comparison
// still enforces a normal limit.
func TestReserveConnectionSlotRespectsLimit(t *testing.T) {
	p := &ConnectionPool{config: &PoolConfig{MaxConnections: 2}}
	for i := 0; i < 2; i++ {
		if !p.reserveConnectionSlot() {
			t.Fatalf("reservation %d refused below the limit", i+1)
		}
	}
	if p.reserveConnectionSlot() {
		t.Fatal("reservation above MaxConnections was accepted")
	}
}
