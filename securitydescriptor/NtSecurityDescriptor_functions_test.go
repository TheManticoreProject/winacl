package securitydescriptor_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/acl"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

func TestNtSecurityDescriptorDaclOperations(t *testing.T) {
	ntsd := securitydescriptor.NewSecurityDescriptor()

	// Test initial empty DACL
	dacl := ntsd.GetDacl()
	if len(dacl.Entries) != 0 {
		t.Errorf("Expected empty DACL initially, got %d entries", len(dacl.Entries))
	}

	// Create and set new DACL
	newDacl := acl.DiscretionaryAccessControlList{}
	entry := ace.AccessControlEntry{}
	entry.Identity.SID.FromString("S-1-5-32-544")
	entry.Header.Type.SetType(acetype.ACE_TYPE_ACCESS_ALLOWED)
	newDacl.AddEntry(entry)

	ntsd.SetDacl(&newDacl)

	// Verify DACL was set correctly
	getDacl := ntsd.GetDacl()
	if len(getDacl.Entries) != 1 {
		t.Errorf("Expected 1 entry in DACL after setting, got %d", len(getDacl.Entries))
	}
	if !getDacl.Entries[0].Equal(&entry) {
		t.Error("DACL entry does not match expected entry")
	}
}

func TestNtSecurityDescriptorSaclOperations(t *testing.T) {
	ntsd := securitydescriptor.NewSecurityDescriptor()

	// Test initial empty SACL
	sacl := ntsd.GetSacl()
	if len(sacl.Entries) != 0 {
		t.Errorf("Expected empty SACL initially, got %d entries", len(sacl.Entries))
	}

	// Create and set new SACL
	newSacl := acl.SystemAccessControlList{}
	entry := ace.AccessControlEntry{}
	entry.Identity.SID.FromString("S-1-5-32-544")
	entry.Header.Type.SetType(acetype.ACE_TYPE_SYSTEM_AUDIT)
	newSacl.AddEntry(entry)

	ntsd.SetSacl(&newSacl)

	// Verify SACL was set correctly
	getSacl := ntsd.GetSacl()
	if len(getSacl.Entries) != 1 {
		t.Errorf("Expected 1 entry in SACL after setting, got %d", len(getSacl.Entries))
	}
	if !getSacl.Entries[0].Equal(&entry) {
		t.Error("SACL entry does not match expected entry")
	}
}

func TestNtSecurityDescriptorEqual(t *testing.T) {
	ntsd1 := securitydescriptor.NewSecurityDescriptor()
	ntsd2 := securitydescriptor.NewSecurityDescriptor()

	// Test equality of empty descriptors
	if !ntsd1.Equal(ntsd2) {
		t.Error("Empty security descriptors should be equal")
	}

	// Add DACL entry to first descriptor
	dacl := acl.DiscretionaryAccessControlList{}
	entry := ace.AccessControlEntry{}
	entry.Identity.SID.FromString("S-1-5-32-544")
	entry.Header.Type.SetType(acetype.ACE_TYPE_ACCESS_ALLOWED)
	dacl.AddEntry(entry)
	ntsd1.SetDacl(&dacl)

	// Descriptors should now be different
	if ntsd1.Equal(ntsd2) {
		t.Error("Security descriptors with different DACLs should not be equal")
	}

	// Make descriptors equal again
	ntsd2.SetDacl(&dacl)
	if !ntsd1.Equal(ntsd2) {
		t.Error("Security descriptors with same DACLs should be equal")
	}

	// Test nil comparison
	if ntsd1.Equal(nil) {
		t.Error("Non-nil descriptor should not equal nil")
	}
}
