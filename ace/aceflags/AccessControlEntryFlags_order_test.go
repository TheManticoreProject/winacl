package aceflags_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace/aceflags"
)

// TestAccessControlEntryFlag_Unmarshal_DeterministicEqual is a regression test
// for the bug where Unmarshal filled the Values/Flags slices in randomized map
// iteration order. Because Equal compares Values positionally, two flags parsed
// from the same byte compared unequal roughly half the time whenever two or
// more bits were set. After the fix the ordering is deterministic, so identical
// bytes always compare Equal and produce an identical string.
func TestAccessControlEntryFlag_Unmarshal_DeterministicEqual(t *testing.T) {
	// 0x03 = OBJECT_INHERIT (0x01) | CONTAINER_INHERIT (0x02): two bits set.
	const raw = 0x03

	var first aceflags.AccessControlEntryFlag
	if _, err := first.Unmarshal([]byte{raw}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i := 0; i < 1000; i++ {
		var other aceflags.AccessControlEntryFlag
		if _, err := other.Unmarshal([]byte{raw}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !first.Equal(&other) {
			t.Fatalf("iteration %d: two flags parsed from byte 0x%02x compare unequal (Values %v vs %v)",
				i, raw, first.Values, other.Values)
		}
		if first.String() != other.String() {
			t.Fatalf("iteration %d: nondeterministic String(): %q vs %q", i, first.String(), other.String())
		}
	}

	// Deterministic order is ascending by flag value: OBJECT_INHERIT then CONTAINER_INHERIT.
	if got := first.String(); got != "OBJECT_INHERIT|CONTAINER_INHERIT" {
		t.Fatalf("String() = %q, want %q", got, "OBJECT_INHERIT|CONTAINER_INHERIT")
	}
}
