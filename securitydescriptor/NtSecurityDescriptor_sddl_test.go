package securitydescriptor

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/object/flags"
)

func TestFromSDDLString_BasicOwnerGroup(t *testing.T) {
	ntsd := NtSecurityDescriptor{}
	_, err := ntsd.FromSDDLString("O:BAG:SY")
	if err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}

	if ntsd.Owner == nil {
		t.Fatal("Owner should not be nil")
	}
	if ntsd.Owner.SID.ToString() != "S-1-5-32-544" {
		t.Errorf("Owner SID = %s, want S-1-5-32-544", ntsd.Owner.SID.ToString())
	}

	if ntsd.Group == nil {
		t.Fatal("Group should not be nil")
	}
	if ntsd.Group.SID.ToString() != "S-1-5-18" {
		t.Errorf("Group SID = %s, want S-1-5-18", ntsd.Group.SID.ToString())
	}
}

func TestFromSDDLString_FullSIDStrings(t *testing.T) {
	ntsd := NtSecurityDescriptor{}
	_, err := ntsd.FromSDDLString("O:S-1-5-32-544G:S-1-5-32-545")
	if err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}

	if ntsd.Owner.SID.ToString() != "S-1-5-32-544" {
		t.Errorf("Owner SID = %s, want S-1-5-32-544", ntsd.Owner.SID.ToString())
	}
	if ntsd.Group.SID.ToString() != "S-1-5-32-545" {
		t.Errorf("Group SID = %s, want S-1-5-32-545", ntsd.Group.SID.ToString())
	}
}

func TestFromSDDLString_WithDACL(t *testing.T) {
	ntsd := NtSecurityDescriptor{}
	_, err := ntsd.FromSDDLString("O:BAG:BAD:(A;OICI;GA;;;BA)(A;OICI;GA;;;SY)")
	if err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}

	if ntsd.DACL == nil {
		t.Fatal("DACL should not be nil")
	}
	if len(ntsd.DACL.Entries) != 2 {
		t.Fatalf("DACL should have 2 entries, got %d", len(ntsd.DACL.Entries))
	}

	// First ACE: A;OICI;GA;;;BA
	ace0 := ntsd.DACL.Entries[0]
	if ace0.Header.Type.Value != acetype.ACE_TYPE_ACCESS_ALLOWED {
		t.Errorf("ACE[0] type = 0x%02x, want ACCESS_ALLOWED (0x00)", ace0.Header.Type.Value)
	}
	if ace0.Header.Flags.RawValue != 0x03 { // OI|CI = 0x01|0x02
		t.Errorf("ACE[0] flags = 0x%02x, want 0x03 (OI|CI)", ace0.Header.Flags.RawValue)
	}
	if ace0.Mask.RawValue != 0x10000000 { // GA
		t.Errorf("ACE[0] mask = 0x%08x, want 0x10000000 (GA)", ace0.Mask.RawValue)
	}
	if ace0.Identity.SID.ToString() != "S-1-5-32-544" {
		t.Errorf("ACE[0] SID = %s, want S-1-5-32-544 (BA)", ace0.Identity.SID.ToString())
	}

	// Second ACE: A;OICI;GA;;;SY
	ace1 := ntsd.DACL.Entries[1]
	if ace1.Identity.SID.ToString() != "S-1-5-18" {
		t.Errorf("ACE[1] SID = %s, want S-1-5-18 (SY)", ace1.Identity.SID.ToString())
	}
}

func TestFromSDDLString_WithSACL(t *testing.T) {
	ntsd := NtSecurityDescriptor{}
	_, err := ntsd.FromSDDLString("S:(AU;SAFA;GA;;;WD)")
	if err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}

	if ntsd.SACL == nil {
		t.Fatal("SACL should not be nil")
	}
	if len(ntsd.SACL.Entries) != 1 {
		t.Fatalf("SACL should have 1 entry, got %d", len(ntsd.SACL.Entries))
	}

	ace0 := ntsd.SACL.Entries[0]
	if ace0.Header.Type.Value != acetype.ACE_TYPE_SYSTEM_AUDIT {
		t.Errorf("ACE type = 0x%02x, want SYSTEM_AUDIT (0x02)", ace0.Header.Type.Value)
	}
	if ace0.Header.Flags.RawValue != 0xC0 { // SA|FA = 0x40|0x80
		t.Errorf("ACE flags = 0x%02x, want 0xC0 (SA|FA)", ace0.Header.Flags.RawValue)
	}
	if ace0.Identity.SID.ToString() != "S-1-1-0" { // WD = Everyone
		t.Errorf("ACE SID = %s, want S-1-1-0 (WD)", ace0.Identity.SID.ToString())
	}
}

func TestFromSDDLString_ObjectACE(t *testing.T) {
	ntsd := NtSecurityDescriptor{}
	_, err := ntsd.FromSDDLString("D:(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;BA)")
	if err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}

	if ntsd.DACL == nil || len(ntsd.DACL.Entries) != 1 {
		t.Fatal("DACL should have 1 entry")
	}

	ace := ntsd.DACL.Entries[0]
	if ace.Header.Type.Value != acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT {
		t.Errorf("ACE type = 0x%02x, want ACCESS_ALLOWED_OBJECT (0x05)", ace.Header.Type.Value)
	}

	// Check object GUID
	if ace.AccessControlObjectType.Flags.Value&flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT == 0 {
		t.Error("Object type flag should be set")
	}
	guidStr := ace.AccessControlObjectType.ObjectType.GUID.ToFormatD()
	if guidStr != "bf967aba-0de6-11d0-a285-00aa003049e2" {
		t.Errorf("Object GUID = %s, want bf967aba-0de6-11d0-a285-00aa003049e2", guidStr)
	}

	// CC|DC = 0x01|0x02 = 0x03
	if ace.Mask.RawValue != 0x03 {
		t.Errorf("ACE mask = 0x%08x, want 0x00000003 (CC|DC)", ace.Mask.RawValue)
	}
}

func TestFromSDDLString_ComplexSDDL(t *testing.T) {
	sddlStr := "O:DAG:DAD:(A;;RPWPCCDCLCRCWOWDSDSW;;;SY)(A;;RPWPCCDCLCRCWOWDSDSW;;;DA)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(A;;RPLCRC;;;AU)S:(AU;SAFA;WDWOSDWPCCDCSW;;;WD)"
	ntsd := NtSecurityDescriptor{}
	_, err := ntsd.FromSDDLString(sddlStr)
	if err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}

	if ntsd.DACL == nil {
		t.Fatal("DACL should not be nil")
	}
	if len(ntsd.DACL.Entries) != 4 {
		t.Errorf("DACL should have 4 entries, got %d", len(ntsd.DACL.Entries))
	}

	if ntsd.SACL == nil {
		t.Fatal("SACL should not be nil")
	}
	if len(ntsd.SACL.Entries) != 1 {
		t.Errorf("SACL should have 1 entry, got %d", len(ntsd.SACL.Entries))
	}
}

func TestToSDDLString_BasicOwnerGroup(t *testing.T) {
	ntsd := NtSecurityDescriptor{}
	_, err := ntsd.FromSDDLString("O:BAG:SY")
	if err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}

	sddlStr, err := ntsd.ToSDDLString()
	if err != nil {
		t.Fatalf("ToSDDLString() error = %v", err)
	}

	if sddlStr != "O:BAG:SY" {
		t.Errorf("ToSDDLString() = %s, want O:BAG:SY", sddlStr)
	}
}

func TestToSDDLString_WithDACL(t *testing.T) {
	input := "O:BAG:BAD:(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)"
	ntsd := NtSecurityDescriptor{}
	_, err := ntsd.FromSDDLString(input)
	if err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}

	sddlStr, err := ntsd.ToSDDLString()
	if err != nil {
		t.Fatalf("ToSDDLString() error = %v", err)
	}

	if sddlStr != input {
		t.Errorf("ToSDDLString() = %s, want %s", sddlStr, input)
	}
}

func TestToSDDLString_WithSACL(t *testing.T) {
	input := "S:(AU;SAFA;GA;;;WD)"
	ntsd := NtSecurityDescriptor{}
	_, err := ntsd.FromSDDLString(input)
	if err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}

	sddlStr, err := ntsd.ToSDDLString()
	if err != nil {
		t.Fatalf("ToSDDLString() error = %v", err)
	}

	if sddlStr != input {
		t.Errorf("ToSDDLString() = %s, want %s", sddlStr, input)
	}
}

func TestToSDDLString_ObjectACE(t *testing.T) {
	input := "D:(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;BA)"
	ntsd := NtSecurityDescriptor{}
	_, err := ntsd.FromSDDLString(input)
	if err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}

	sddlStr, err := ntsd.ToSDDLString()
	if err != nil {
		t.Fatalf("ToSDDLString() error = %v", err)
	}

	if sddlStr != input {
		t.Errorf("ToSDDLString() = %s, want %s", sddlStr, input)
	}
}

func TestRoundTrip_ComplexSDDL(t *testing.T) {
	// Test round-trip for various SDDL strings
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Owner and group only",
			input: "O:BAG:SY",
		},
		{
			name:  "DACL with multiple ACEs",
			input: "O:BAG:BAD:(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)",
		},
		{
			name:  "DACL and SACL",
			input: "O:BAG:BAD:(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)S:(AU;SAFA;GA;;;WD)",
		},
		{
			name:  "Full SID strings that are not well-known",
			input: "O:S-1-5-21-123-456-789-1000G:S-1-5-21-123-456-789-1001D:(A;ID;GA;;;S-1-5-21-123-456-789-1002)",
		},
		{
			name:  "Object ACE with GUID",
			input: "D:(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;BA)",
		},
		{
			name:  "Mandatory label",
			input: "S:(ML;;NW;;;HI)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ntsd := NtSecurityDescriptor{}
			_, err := ntsd.FromSDDLString(tt.input)
			if err != nil {
				t.Fatalf("FromSDDLString(%s) error = %v", tt.input, err)
			}

			output, err := ntsd.ToSDDLString()
			if err != nil {
				t.Fatalf("ToSDDLString() error = %v", err)
			}

			if output != tt.input {
				t.Errorf("Round-trip failed:\n  input:  %s\n  output: %s", tt.input, output)
			}
		})
	}
}

func TestFromSDDLString_MarshalRoundTrip(t *testing.T) {
	// Parse SDDL, marshal to binary, unmarshal from binary, convert back to SDDL
	input := "O:BAG:BAD:(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)"

	ntsd1 := NtSecurityDescriptor{}
	_, err := ntsd1.FromSDDLString(input)
	if err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}

	// Marshal to binary
	data, err := ntsd1.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal from binary
	ntsd2 := NtSecurityDescriptor{}
	_, err = ntsd2.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Convert back to SDDL
	output, err := ntsd2.ToSDDLString()
	if err != nil {
		t.Fatalf("ToSDDLString() error = %v", err)
	}

	if output != input {
		t.Errorf("SDDL->Binary->SDDL round-trip failed:\n  input:  %s\n  output: %s", input, output)
	}
}

func TestSDDLtoNtSecurityDescriptor_via_sddl_package(t *testing.T) {
	// Test the sddl package wrapper functions work
	ntsd := NtSecurityDescriptor{}
	_, err := ntsd.FromSDDLString("O:BAG:BAD:(A;;GA;;;WD)")
	if err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}

	if ntsd.Owner == nil || ntsd.Owner.SID.ToString() != "S-1-5-32-544" {
		t.Error("Owner should be BA (S-1-5-32-544)")
	}
	if ntsd.DACL == nil || len(ntsd.DACL.Entries) != 1 {
		t.Error("Should have 1 DACL entry")
	}
}
