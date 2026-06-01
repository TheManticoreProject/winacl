package acl_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/acl"
	"github.com/TheManticoreProject/winacl/acl/revision"
)

// largeCallbackACE builds a callback ACE carrying appDataLen bytes of
// ApplicationData. With appDataLen well under 65535 each ACE marshals fine; a
// few of them combined push the ACL body past the uint16 AclSize limit.
func largeCallbackACE(appDataLen int) ace.AccessControlEntry {
	e := ace.AccessControlEntry{}
	e.Header.Type.Value = acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK
	e.Mask.SetRights([]uint32{0x00000001})
	e.Identity.SID.FromString("S-1-1-0")
	e.ApplicationData = make([]byte, appDataLen)
	return e
}

// TestDACL_Marshal_OversizedAclSize verifies that marshalling a DACL whose body
// exceeds the uint16 AclSize field returns an error instead of wrapping.
func TestDACL_Marshal_OversizedAclSize(t *testing.T) {
	dacl := &acl.DiscretionaryAccessControlList{}
	dacl.Header.Revision.SetRevision(revision.ACL_REVISION_DS)
	for i := 0; i < 3; i++ {
		dacl.AddEntry(largeCallbackACE(23000)) // ~23020 bytes each, < 65535
	}

	if _, err := dacl.Marshal(); err == nil {
		t.Error("Marshal() = nil error, want error for DACL exceeding the uint16 AclSize maximum")
	}
}

// TestSACL_Marshal_OversizedAclSize verifies the same guard for the SACL.
func TestSACL_Marshal_OversizedAclSize(t *testing.T) {
	sacl := &acl.SystemAccessControlList{}
	sacl.Header.Revision.SetRevision(revision.ACL_REVISION_DS)
	for i := 0; i < 3; i++ {
		sacl.AddEntry(largeCallbackACE(23000))
	}

	if _, err := sacl.Marshal(); err == nil {
		t.Error("Marshal() = nil error, want error for SACL exceeding the uint16 AclSize maximum")
	}
}

// TestDACL_Marshal_NormalSizeOK verifies the guard does not affect a normal DACL.
func TestDACL_Marshal_NormalSizeOK(t *testing.T) {
	dacl := &acl.DiscretionaryAccessControlList{}
	dacl.Header.Revision.SetRevision(revision.ACL_REVISION_DS)
	entry := ace.AccessControlEntry{}
	entry.Header.Type.Value = acetype.ACE_TYPE_ACCESS_ALLOWED
	entry.Mask.SetRights([]uint32{0x00000001})
	entry.Identity.SID.FromString("S-1-1-0")
	dacl.AddEntry(entry)

	if _, err := dacl.Marshal(); err != nil {
		t.Fatalf("Marshal() of a normal DACL error = %v", err)
	}
}
