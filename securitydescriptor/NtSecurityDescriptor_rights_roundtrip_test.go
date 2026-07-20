package securitydescriptor

import (
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/ace/acetype"
)

// TestSddlRights_RoundTrip verifies that every mask emitted by sddlRightsToString
// parses back to the same value. Previously masks that were not fully covered by
// known aliases were rendered as a mix of aliases plus a trailing "0x..." (e.g.
// "RCWPLO0x00100000" for FILE_GENERIC_EXECUTE), which sddlParseRights rejected.
func TestSddlRights_RoundTrip(t *testing.T) {
	masks := []uint32{
		0x001200A0, // FILE_GENERIC_EXECUTE (FX)
		0x00120089, // FILE_GENERIC_READ (FR)
		0x00120116, // FILE_GENERIC_WRITE (FW)
		0x001F01FF, // FILE_ALL_ACCESS (FA)
		0x000F003F, // KEY_ALL_ACCESS (KA)
		0x00020019, // KEY_READ / KEY_EXECUTE
		0x10000000, // GENERIC_ALL (GA)
		0x00020000, // READ_CONTROL (RC)
		0x00030000, // RC | SD
		0x000e0000, // WD | WO | RC
		0x00100000, // SYNCHRONIZE only (no alias -> hex)
		0x12345678, // arbitrary
		0xFFFFFFFF, // all bits
	}

	for _, m := range masks {
		s := sddlRightsToString(m, acetype.ACE_TYPE_ACCESS_ALLOWED)
		if strings.Contains(s, "0x") && !strings.HasPrefix(s, "0x") {
			t.Errorf("mask 0x%08x -> %q mixes aliases with a hex remainder (not parseable)", m, s)
		}
		got, err := sddlParseRights(s)
		if err != nil {
			t.Errorf("mask 0x%08x -> %q failed to parse back: %v", m, s, err)
			continue
		}
		if got != m {
			t.Errorf("rights round-trip mismatch: 0x%08x -> %q -> 0x%08x", m, s, got)
		}
	}
}

// TestSddlRights_ObjectSpecificAliases checks that the object-specific composite
// masks render as their Windows aliases.
func TestSddlRights_ObjectSpecificAliases(t *testing.T) {
	cases := map[uint32]string{
		0x001200A0: "FX",
		0x00120089: "FR",
		0x00120116: "FW",
		0x001F01FF: "FA",
		0x000F003F: "KA",
	}
	for mask, want := range cases {
		if got := sddlRightsToString(mask, acetype.ACE_TYPE_ACCESS_ALLOWED); got != want {
			t.Errorf("sddlRightsToString(0x%08x) = %q, want %q", mask, got, want)
		}
	}
}

// TestSddlRights_FXEndToEnd verifies a full SDDL round-trip of an ACE whose
// rights are FILE_GENERIC_EXECUTE, which previously broke re-parsing.
func TestSddlRights_FXEndToEnd(t *testing.T) {
	const sddl = `D:(A;;FX;;;S-1-1-0)`

	ntsd := &NtSecurityDescriptor{}
	if _, err := ntsd.FromSDDLString(sddl); err != nil {
		t.Fatalf("FromSDDLString error = %v", err)
	}
	out, err := ntsd.ToSDDLString()
	if err != nil {
		t.Fatalf("ToSDDLString error = %v", err)
	}
	if !strings.Contains(out, ";FX;") {
		t.Fatalf("expected rights to serialize as FX, got %q", out)
	}

	ntsd2 := &NtSecurityDescriptor{}
	if _, err := ntsd2.FromSDDLString(out); err != nil {
		t.Fatalf("re-FromSDDLString(%q) error = %v", out, err)
	}
	if ntsd.DACL.Entries[0].Mask.RawValue != ntsd2.DACL.Entries[0].Mask.RawValue {
		t.Fatalf("mask not stable across round-trip: 0x%08x vs 0x%08x",
			ntsd.DACL.Entries[0].Mask.RawValue, ntsd2.DACL.Entries[0].Mask.RawValue)
	}
}
