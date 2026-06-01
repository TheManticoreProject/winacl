package acl_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/acl"
	"github.com/TheManticoreProject/winacl/acl/revision"
)

// buildSingleEntryDACL returns the marshalled bytes of a DACL containing exactly
// one ACCESS_ALLOWED ACE, along with the marshalled length.
func buildSingleEntryDACL(t *testing.T) []byte {
	t.Helper()

	dacl := &acl.DiscretionaryAccessControlList{}
	dacl.Header.Revision.SetRevision(revision.ACL_REVISION_DS)

	entry := ace.AccessControlEntry{}
	entry.Header.Type.Value = acetype.ACE_TYPE_ACCESS_ALLOWED
	entry.Mask.SetRights([]uint32{0x00000001})
	entry.Identity.SID.FromString("S-1-1-0")
	dacl.AddEntry(entry)

	data, err := dacl.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return data
}

// TestDACL_Unmarshal_TrailingBytesNotConsumed verifies that Unmarshal stops at
// AclSize and does not read trailing bytes (e.g. the Owner/Group SIDs that
// follow the ACL inside a security descriptor).
func TestDACL_Unmarshal_TrailingBytesNotConsumed(t *testing.T) {
	good := buildSingleEntryDACL(t)

	// Simulate the ACL being followed by other descriptor components.
	withTrailing := append(append([]byte{}, good...), 0xDE, 0xAD, 0xBE, 0xEF)

	dacl := &acl.DiscretionaryAccessControlList{}
	consumed, err := dacl.Unmarshal(withTrailing)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if consumed != len(good) {
		t.Errorf("Unmarshal() consumed = %d, want %d (AclSize, trailing bytes excluded)", consumed, len(good))
	}
	if consumed != int(dacl.Header.AclSize) {
		t.Errorf("Unmarshal() consumed = %d, want AclSize = %d", consumed, dacl.Header.AclSize)
	}
	if len(dacl.Entries) != 1 {
		t.Errorf("Unmarshal() parsed %d entries, want 1", len(dacl.Entries))
	}
}

// TestDACL_Unmarshal_AceCountExceedsAclSize verifies that an AceCount which
// overstates the ACEs that fit within AclSize is rejected instead of reading
// past the ACL.
func TestDACL_Unmarshal_AceCountExceedsAclSize(t *testing.T) {
	good := buildSingleEntryDACL(t)

	// The DACL header is 8 bytes; AceCount is the little-endian uint16 at offset
	// 4. Bump it from 1 to 2 without changing AclSize, then append bytes that
	// look like they could be another ACE so the over-read would otherwise have
	// data to consume.
	corrupt := append(append([]byte{}, good...), make([]byte, 32)...)
	corrupt[4] = 0x02
	corrupt[5] = 0x00

	dacl := &acl.DiscretionaryAccessControlList{}
	if _, err := dacl.Unmarshal(corrupt); err == nil {
		t.Error("Unmarshal() = nil error, want error when AceCount exceeds AclSize")
	}
}
