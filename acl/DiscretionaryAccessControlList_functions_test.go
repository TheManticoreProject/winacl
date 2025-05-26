package acl_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/acl"
)

func TestDACLClearEntries(t *testing.T) {
	dacl := acl.DiscretionaryAccessControlList{}

	// Add some test entries
	entry1 := ace.AccessControlEntry{}
	entry2 := ace.AccessControlEntry{}

	dacl.AddEntry(entry1)
	dacl.AddEntry(entry2)

	if len(dacl.Entries) != 2 {
		t.Errorf("Expected 2 entries after adding, got %d", len(dacl.Entries))
	}

	if dacl.Header.AceCount != 2 {
		t.Errorf("Expected AceCount of 2 after adding, got %d", dacl.Header.AceCount)
	}

	// Clear entries
	dacl.ClearEntries()

	if len(dacl.Entries) != 0 {
		t.Errorf("Expected 0 entries after clearing, got %d", len(dacl.Entries))
	}

	if dacl.Header.AceCount != 0 {
		t.Errorf("Expected AceCount of 0 after clearing, got %d", dacl.Header.AceCount)
	}
}

func TestDACLAddEntry(t *testing.T) {
	dacl := acl.DiscretionaryAccessControlList{}

	entry1 := ace.AccessControlEntry{}
	dacl.AddEntry(entry1)

	if len(dacl.Entries) != 1 {
		t.Errorf("Expected 1 entry after adding, got %d", len(dacl.Entries))
	}

	if dacl.Header.AceCount != 1 {
		t.Errorf("Expected AceCount of 1 after adding, got %d", dacl.Header.AceCount)
	}

	if dacl.Entries[0].Index != 1 {
		t.Errorf("Expected first entry index to be 1, got %d", dacl.Entries[0].Index)
	}

	entry2 := ace.AccessControlEntry{}
	dacl.AddEntry(entry2)

	if len(dacl.Entries) != 2 {
		t.Errorf("Expected 2 entries after adding second entry, got %d", len(dacl.Entries))
	}

	if dacl.Header.AceCount != 2 {
		t.Errorf("Expected AceCount of 2 after adding second entry, got %d", dacl.Header.AceCount)
	}

	if dacl.Entries[1].Index != 2 {
		t.Errorf("Expected second entry index to be 2, got %d", dacl.Entries[1].Index)
	}
}

func TestDACLRemoveEntry(t *testing.T) {
	dacl := acl.DiscretionaryAccessControlList{}

	// Add two entries
	entry1 := ace.AccessControlEntry{}
	entry1.Index = 1
	entry1.Identity.SID.FromString("S-1-5-32-544")
	entry1.Header.Type.SetType(acetype.ACE_TYPE_ACCESS_ALLOWED)
	dacl.AddEntry(entry1)

	entry2 := ace.AccessControlEntry{}
	entry2.Index = 2
	entry2.Identity.SID.FromString("S-1-5-32-545")
	entry2.Header.Type.SetType(acetype.ACE_TYPE_ACCESS_ALLOWED)
	dacl.AddEntry(entry2)

	// Verify initial state
	if len(dacl.Entries) != 2 {
		t.Errorf("Expected 2 entries initially, got %d", len(dacl.Entries))
	}

	if dacl.Header.AceCount != 2 {
		t.Errorf("Expected AceCount of 2 initially, got %d", dacl.Header.AceCount)
	}

	// Remove first entry
	dacl.RemoveEntry(entry1)

	// Verify state after removal
	if len(dacl.Entries) != 1 {
		t.Errorf("Expected 1 entry after removal, got %d", len(dacl.Entries))
	}

	if dacl.Header.AceCount != 1 {
		t.Errorf("Expected AceCount of 1 after removal, got %d", dacl.Header.AceCount)
	}

	// Verify remaining entry is entry2
	if !dacl.Entries[0].Equal(&entry2) {
		t.Error("Expected remaining entry to be entry2")
	}

	// Try removing non-existent entry
	nonExistentEntry := ace.AccessControlEntry{}
	nonExistentEntry.Index = 99
	dacl.RemoveEntry(nonExistentEntry)

	// Verify state unchanged after attempting to remove non-existent entry
	if len(dacl.Entries) != 1 {
		t.Errorf("Expected 1 entry after removing non-existent entry, got %d", len(dacl.Entries))
	}

	if dacl.Header.AceCount != 1 {
		t.Errorf("Expected AceCount of 1 after removing non-existent entry, got %d", dacl.Header.AceCount)
	}
}
