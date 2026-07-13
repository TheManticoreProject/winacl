package securitydescriptor_test

import (
	"encoding/hex"
	"testing"

	"github.com/TheManticoreProject/winacl/securitydescriptor"
	"github.com/TheManticoreProject/winacl/securitydescriptor/control"
)

// TestNtSecurityDescriptor_Marshal_PresentEmptyDACL is a regression test for
// the bug where Marshal dropped a present-but-empty DACL (SE_DACL_PRESENT set,
// zero ACEs), setting OffsetDacl = 0 while leaving SE_DACL_PRESENT in Control.
// That corrupted the descriptor and converted an empty DACL (deny-all) into an
// absent NULL DACL (allow-all) on the next parse.
//
// Wire layout (28 bytes):
//
//	Revision   = 0x01
//	Sbz1       = 0x00
//	Control    = 0x8004 (SE_SELF_RELATIVE | SE_DACL_PRESENT), little-endian 0x04 0x80
//	OffsetOwner= 0
//	OffsetGroup= 0
//	OffsetSacl = 0
//	OffsetDacl = 20
//	DACL       = AclRevision 0x02, Sbz1 0x00, AclSize 8, AceCount 0, Sbz2 0
func TestNtSecurityDescriptor_Marshal_PresentEmptyDACL(t *testing.T) {
	const input = "0100048000000000000000000000000014000000" + "0200080000000000"

	inputBytes, err := hex.DecodeString(input)
	if err != nil {
		t.Fatalf("failed to decode input: %v", err)
	}

	ntsd := &securitydescriptor.NtSecurityDescriptor{}
	if _, err := ntsd.Unmarshal(inputBytes); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if ntsd.DACL == nil {
		t.Fatal("parsed DACL is nil; a present DACL (SE_DACL_PRESENT set) must be non-nil")
	}
	if !ntsd.Header.Control.HasControl(control.NT_SECURITY_DESCRIPTOR_CONTROL_DP) {
		t.Fatal("SE_DACL_PRESENT must remain set after Unmarshal")
	}

	out, err := ntsd.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// The present-but-empty DACL must survive Marshal: the output must be
	// byte-identical to the input (offset preserved, DACL bytes re-emitted).
	if got := hex.EncodeToString(out); got != input {
		t.Fatalf("Marshal() = %s, want %s (present-but-empty DACL was dropped)", got, input)
	}

	// The control bit and the DACL offset must stay consistent.
	if ntsd.Header.OffsetDacl == 0 {
		t.Fatal("OffsetDacl = 0 after Marshal; a present DACL must keep a non-zero offset")
	}

	// Re-parsing the marshalled bytes must still yield a present (non-nil) DACL,
	// i.e. the empty-vs-NULL DACL semantics are preserved across the round-trip.
	reparsed := &securitydescriptor.NtSecurityDescriptor{}
	if _, err := reparsed.Unmarshal(out); err != nil {
		t.Fatalf("re-Unmarshal() error = %v", err)
	}
	if reparsed.DACL == nil {
		t.Fatal("re-parsed DACL is nil; empty DACL was silently converted to a NULL (allow-all) DACL")
	}
	if !reparsed.Header.Control.HasControl(control.NT_SECURITY_DESCRIPTOR_CONTROL_DP) {
		t.Fatal("SE_DACL_PRESENT lost across round-trip")
	}
}
