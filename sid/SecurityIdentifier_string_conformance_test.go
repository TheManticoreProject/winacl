package sid_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/sid"
)

// TestSID_ToString_NoSpuriousRID is a regression test for ToString fabricating a
// trailing "-0" for a SID with SubAuthorityCount == 0. A bare NT Authority SID
// (binary: revision 1, 0 sub-authorities, identifier authority 5) must render
// as "S-1-5", not "S-1-5-0" (which is the canonical string of a different SID).
func TestSID_ToString_NoSpuriousRID(t *testing.T) {
	// 01 00 000000000005 : Revision 1, SubAuthorityCount 0, IdentifierAuthority 5.
	bare := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}

	s := &sid.SID{}
	if _, err := s.Unmarshal(bare); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if s.SubAuthorityCount != 0 {
		t.Fatalf("SubAuthorityCount = %d, want 0", s.SubAuthorityCount)
	}
	if got := s.ToString(); got != "S-1-5" {
		t.Fatalf("ToString() = %q, want %q", got, "S-1-5")
	}

	// A normal SID must still include its RID.
	normal := &sid.SID{}
	if err := normal.FromString("S-1-5-32-544"); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}
	if got := normal.ToString(); got != "S-1-5-32-544" {
		t.Fatalf("ToString() = %q, want %q", got, "S-1-5-32-544")
	}
}

// TestSID_HexIdentifierAuthority is a regression test for the identifier
// authority >= 2^32 not being formatted/parsed in the hexadecimal form that
// MS-DTYP 2.4.2.1 mandates ("0x" followed by 12 hex digits).
func TestSID_HexIdentifierAuthority(t *testing.T) {
	// 2^40 = 0x10000000000, which is >= 2^32 and within the 48-bit field.
	const authority = uint64(1) << 40
	const wantStr = "S-1-0x010000000000-1-2"

	// ToString must emit the hex form.
	s := &sid.SID{}
	if err := s.FromString("S-1-1099511627776-1-2"); err != nil {
		t.Fatalf("FromString(decimal) error = %v", err)
	}
	if s.IdentifierAuthority.Value != authority {
		t.Fatalf("parsed authority = %d, want %d", s.IdentifierAuthority.Value, authority)
	}
	if got := s.ToString(); got != wantStr {
		t.Fatalf("ToString() = %q, want %q", got, wantStr)
	}

	// FromString must accept the hex form and decode the same value.
	h := &sid.SID{}
	if err := h.FromString(wantStr); err != nil {
		t.Fatalf("FromString(hex) error = %v", err)
	}
	if h.IdentifierAuthority.Value != authority {
		t.Fatalf("hex-parsed authority = %d, want %d", h.IdentifierAuthority.Value, authority)
	}

	// Round-trip: the hex string re-serializes and re-parses to the same value.
	if got := h.ToString(); got != wantStr {
		t.Fatalf("hex round-trip ToString() = %q, want %q", got, wantStr)
	}

	// A value < 2^32 must still be decimal.
	dec := &sid.SID{}
	if err := dec.FromString("S-1-5-18"); err != nil {
		t.Fatalf("FromString() error = %v", err)
	}
	if got := dec.ToString(); got != "S-1-5-18" {
		t.Fatalf("ToString() = %q, want %q (small authority must stay decimal)", got, "S-1-5-18")
	}
}
