package mask

import (
	"testing"
)

// TestAccessControlMask_Unmarshal_RawBytesFourBytes is a regression test for
// Unmarshal aliasing the whole remaining ACE body into RawBytes. The ACCESS_MASK
// is a fixed 4-byte field (MS-DTYP 2.4.3), so RawBytes must hold exactly those 4
// bytes; otherwise Equal (a byte comparison of RawBytes) reports two masks with
// the same value but different ACE tails as unequal.
func TestAccessControlMask_Unmarshal_RawBytesFourBytes(t *testing.T) {
	// 0x000f01ff followed by trailing bytes that belong to the SID / app data.
	a := AccessControlMask{}
	if _, err := a.Unmarshal([]byte{0xff, 0x01, 0x0f, 0x00, 0xaa, 0xbb, 0xcc, 0xdd}); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	b := AccessControlMask{}
	if _, err := b.Unmarshal([]byte{0xff, 0x01, 0x0f, 0x00, 0x11, 0x22}); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if len(a.RawBytes) != 4 {
		t.Fatalf("RawBytes length = %d, want 4", len(a.RawBytes))
	}
	if a.RawValue != 0x000f01ff || b.RawValue != 0x000f01ff {
		t.Fatalf("RawValue mismatch: 0x%08x / 0x%08x", a.RawValue, b.RawValue)
	}
	if !a.Equal(&b) {
		t.Fatalf("masks with identical value 0x%08x but different ACE tails compare unequal (RawBytes %x vs %x)",
			a.RawValue, a.RawBytes, b.RawBytes)
	}
}
