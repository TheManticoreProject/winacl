package control_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/securitydescriptor/control"
)

// TestControl_Equal_Deterministic is a regression test for Equal comparing the
// Values/Flags slices positionally. Those slices are filled from randomized Go
// map iteration, so two controls decoded from identical bytes compared unequal
// a large fraction of the time. Equality must depend only on RawValue.
func TestControl_Equal_Deterministic(t *testing.T) {
	// 0x8004 = SE_SELF_RELATIVE | SE_DACL_PRESENT (two bits, so slice order can differ).
	raw := []byte{0x04, 0x80}

	var reference control.NtSecurityDescriptorControl
	if _, err := reference.Unmarshal(raw); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	for i := 0; i < 1000; i++ {
		var other control.NtSecurityDescriptorControl
		if _, err := other.Unmarshal(raw); err != nil {
			t.Fatalf("Unmarshal error = %v", err)
		}
		if !reference.Equal(&other) {
			t.Fatalf("iteration %d: controls decoded from identical bytes compared unequal (Values %v vs %v)",
				i, reference.Values, other.Values)
		}
	}
}

// TestControl_Equal_DifferentValues verifies Equal still distinguishes different
// control words.
func TestControl_Equal_DifferentValues(t *testing.T) {
	var a, b control.NtSecurityDescriptorControl
	if _, err := a.Unmarshal([]byte{0x04, 0x80}); err != nil { // 0x8004
		t.Fatal(err)
	}
	if _, err := b.Unmarshal([]byte{0x14, 0x80}); err != nil { // 0x8014
		t.Fatal(err)
	}
	if a.Equal(&b) {
		t.Error("controls with different RawValue must not be Equal")
	}
}
