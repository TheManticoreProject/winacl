package securitydescriptor

import (
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/securitydescriptor/control"
)

// TestCutSDDL_ColonInLiteral is a regression test for cutSDDL misattributing an
// O:/G:/D:/S: substring that occurs inside a conditional-expression or
// resource-attribute quoted literal (e.g. a Windows path "D:\\..." or a value
// like "S:ecret") as a top-level section marker, which corrupted parsing.
func TestCutSDDL_ColonInLiteral(t *testing.T) {
	cases := []string{
		`D:(XA;;FR;;;WD;(@User.Title=="S:enior"))`,
		`D:(RA;;;;;WD;("x",TS,0,"S:ecret"))`,
		`D:(RA;;;;;WD;("path",TS,0,"D:\Windows"))`,
		`D:(XA;;FR;;;WD;(@User.Path=="G:foo" || @User.Path=="O:bar"))`,
	}
	for _, sddl := range cases {
		t.Run(sddl, func(t *testing.T) {
			ntsd := &NtSecurityDescriptor{}
			if _, err := ntsd.FromSDDLString(sddl); err != nil {
				t.Fatalf("FromSDDLString(%q) error = %v", sddl, err)
			}
			if ntsd.DACL == nil || len(ntsd.DACL.Entries) != 1 {
				t.Fatalf("expected one DACL entry, got %+v", ntsd.DACL)
			}
			if len(ntsd.DACL.Entries[0].ApplicationData) == 0 {
				t.Fatal("ACE ApplicationData is empty; the 7th field was lost")
			}
		})
	}
}

// TestCutSDDL_ParenInQuotedLiteral verifies that parentheses inside a quoted
// literal are treated as data, not ACE delimiters.
func TestCutSDDL_ParenInQuotedLiteral(t *testing.T) {
	const sddl = `D:(XA;;FR;;;WD;(@User.Note=="a)b(c"))`
	ntsd := &NtSecurityDescriptor{}
	if _, err := ntsd.FromSDDLString(sddl); err != nil {
		t.Fatalf("FromSDDLString error = %v", err)
	}
	if ntsd.DACL == nil || len(ntsd.DACL.Entries) != 1 {
		t.Fatalf("expected one DACL entry, got %+v", ntsd.DACL)
	}
}

// TestFromSDDLString_PresentEmptyDACL is a regression test for a present-but-
// empty DACL/SACL being dropped: "D:"/"S:" with no ACEs must create an empty
// (present) ACL and set SE_DACL_PRESENT/SE_SACL_PRESENT, round-tripping back.
func TestFromSDDLString_PresentEmptyDACL(t *testing.T) {
	const sddl = `O:SYG:SYD:S:`
	ntsd := &NtSecurityDescriptor{}
	if _, err := ntsd.FromSDDLString(sddl); err != nil {
		t.Fatalf("FromSDDLString error = %v", err)
	}
	if ntsd.DACL == nil {
		t.Fatal("present-but-empty DACL was dropped (DACL is nil)")
	}
	if ntsd.SACL == nil {
		t.Fatal("present-but-empty SACL was dropped (SACL is nil)")
	}
	if !ntsd.Header.Control.HasControl(control.NT_SECURITY_DESCRIPTOR_CONTROL_DP) {
		t.Error("SE_DACL_PRESENT not set for a present empty DACL")
	}
	if !ntsd.Header.Control.HasControl(control.NT_SECURITY_DESCRIPTOR_CONTROL_SP) {
		t.Error("SE_SACL_PRESENT not set for a present empty SACL")
	}

	out, err := ntsd.ToSDDLString()
	if err != nil {
		t.Fatalf("ToSDDLString error = %v", err)
	}
	if !strings.Contains(out, "D:") || !strings.Contains(out, "S:") {
		t.Fatalf("present empty DACL/SACL lost on re-serialization: %q", out)
	}
}

// TestFromSDDLString_AbsentDACL verifies an absent D: stays absent (NULL DACL).
func TestFromSDDLString_AbsentDACL(t *testing.T) {
	const sddl = `O:SYG:SY`
	ntsd := &NtSecurityDescriptor{}
	if _, err := ntsd.FromSDDLString(sddl); err != nil {
		t.Fatalf("FromSDDLString error = %v", err)
	}
	if ntsd.DACL != nil {
		t.Error("absent DACL should remain nil (NULL DACL)")
	}
	if ntsd.Header.Control.HasControl(control.NT_SECURITY_DESCRIPTOR_CONTROL_DP) {
		t.Error("SE_DACL_PRESENT must not be set when no D: token is present")
	}
}
