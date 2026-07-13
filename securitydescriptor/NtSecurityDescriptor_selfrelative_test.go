package securitydescriptor_test

import (
	"encoding/binary"
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/acl"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
	"github.com/TheManticoreProject/winacl/securitydescriptor/control"
)

// TestNtSecurityDescriptor_Marshal_SetsSelfRelative verifies that a descriptor
// built programmatically and marshalled carries SE_SELF_RELATIVE, since Marshal
// always emits self-relative (offset-based) layout. Previously Marshal left the
// control word untouched, so a NewSecurityDescriptor()+SetDacl()+Marshal()
// produced self-relative bytes advertised as absolute-format (SR clear).
func TestNtSecurityDescriptor_Marshal_SetsSelfRelative(t *testing.T) {
	ntsd := securitydescriptor.NewSecurityDescriptor()

	dacl := &acl.DiscretionaryAccessControlList{}
	a := ace.AccessControlEntry{}
	a.Header.Type.Value = acetype.ACE_TYPE_ACCESS_ALLOWED
	a.Identity.SID.FromString("S-1-1-0")
	dacl.AddEntry(a)
	ntsd.SetDacl(dacl)

	data, err := ntsd.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// SetDacl must set SE_DACL_PRESENT; Marshal must set SE_SELF_RELATIVE.
	if !ntsd.Header.Control.HasControl(control.NT_SECURITY_DESCRIPTOR_CONTROL_SR) {
		t.Error("SE_SELF_RELATIVE (0x8000) not set after Marshal")
	}
	if !ntsd.Header.Control.HasControl(control.NT_SECURITY_DESCRIPTOR_CONTROL_DP) {
		t.Error("SE_DACL_PRESENT (0x0004) not set after SetDacl")
	}

	// The serialized control word must carry both bits.
	ctrl := binary.LittleEndian.Uint16(data[2:4])
	const wantMask = control.NT_SECURITY_DESCRIPTOR_CONTROL_SR | control.NT_SECURITY_DESCRIPTOR_CONTROL_DP
	if ctrl&wantMask != wantMask {
		t.Errorf("serialized control = 0x%04x, want SE_SELF_RELATIVE|SE_DACL_PRESENT (0x%04x) set", ctrl, wantMask)
	}
}

// TestNtSecurityDescriptor_SetSacl_SetsPresent verifies SetSacl sets SE_SACL_PRESENT.
func TestNtSecurityDescriptor_SetSacl_SetsPresent(t *testing.T) {
	ntsd := securitydescriptor.NewSecurityDescriptor()
	ntsd.SetSacl(&acl.SystemAccessControlList{})

	if !ntsd.Header.Control.HasControl(control.NT_SECURITY_DESCRIPTOR_CONTROL_SP) {
		t.Error("SE_SACL_PRESENT (0x0010) not set after SetSacl")
	}
}
