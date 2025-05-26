package acl_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/acl"
)

func TestSACLClearEntries(t *testing.T) {
	sacl := acl.SystemAccessControlList{}

	// Add some test entries
	entry1 := ace.AccessControlEntry{}
	entry2 := ace.AccessControlEntry{}

	sacl.AddEntry(entry1)
	sacl.AddEntry(entry2)

	if len(sacl.Entries) != 2 {
		t.Errorf("Expected 2 entries after adding, got %d", len(sacl.Entries))
	}

	if sacl.Header.AceCount != 2 {
		t.Errorf("Expected AceCount of 2 after adding, got %d", sacl.Header.AceCount)
	}

	// Clear entries
	sacl.ClearEntries()

	if len(sacl.Entries) != 0 {
		t.Errorf("Expected 0 entries after clearing, got %d", len(sacl.Entries))
	}

	if sacl.Header.AceCount != 0 {
		t.Errorf("Expected AceCount of 0 after clearing, got %d", sacl.Header.AceCount)
	}
}

func TestSACLAddEntry(t *testing.T) {
	sacl := acl.SystemAccessControlList{}

	entry1 := ace.AccessControlEntry{}
	sacl.AddEntry(entry1)

	if len(sacl.Entries) != 1 {
		t.Errorf("Expected 1 entry after adding, got %d", len(sacl.Entries))
	}

	if sacl.Header.AceCount != 1 {
		t.Errorf("Expected AceCount of 1 after adding, got %d", sacl.Header.AceCount)
	}

	if sacl.Entries[0].Index != 1 {
		t.Errorf("Expected first entry index to be 1, got %d", sacl.Entries[0].Index)
	}

	entry2 := ace.AccessControlEntry{}
	sacl.AddEntry(entry2)

	if len(sacl.Entries) != 2 {
		t.Errorf("Expected 2 entries after adding second entry, got %d", len(sacl.Entries))
	}

	if sacl.Header.AceCount != 2 {
		t.Errorf("Expected AceCount of 2 after adding second entry, got %d", sacl.Header.AceCount)
	}

	if sacl.Entries[1].Index != 2 {
		t.Errorf("Expected second entry index to be 2, got %d", sacl.Entries[1].Index)
	}
}

func TestSACLRemoveEntry(t *testing.T) {
	sacl := acl.SystemAccessControlList{}

	// Add two entries
	entry1 := ace.AccessControlEntry{}
	entry1.Index = 1
	sacl.AddEntry(entry1)

	entry2 := ace.AccessControlEntry{}
	entry2.Index = 2
	sacl.AddEntry(entry2)

	// Verify initial state
	if len(sacl.Entries) != 2 {
		t.Errorf("Expected 2 entries initially, got %d", len(sacl.Entries))
	}

	if sacl.Header.AceCount != 2 {
		t.Errorf("Expected AceCount of 2 initially, got %d", sacl.Header.AceCount)
	}

	// Remove first entry
	sacl.RemoveEntry(entry1)

	// Verify state after removal
	if len(sacl.Entries) != 1 {
		t.Errorf("Expected 1 entry after removal, got %d", len(sacl.Entries))
	}

	if sacl.Header.AceCount != 1 {
		t.Errorf("Expected AceCount of 1 after removal, got %d", sacl.Header.AceCount)
	}

	// Verify remaining entry is entry2
	if !sacl.Entries[0].Equal(&entry2) {
		t.Error("Expected remaining entry to be entry2")
	}

	// Try removing non-existent entry
	nonExistentEntry := ace.AccessControlEntry{}
	nonExistentEntry.Index = 99
	sacl.RemoveEntry(nonExistentEntry)

	// Verify state unchanged after attempting to remove non-existent entry
	if len(sacl.Entries) != 1 {
		t.Errorf("Expected 1 entry after removing non-existent entry, got %d", len(sacl.Entries))
	}

	if sacl.Header.AceCount != 1 {
		t.Errorf("Expected AceCount of 1 after removing non-existent entry, got %d", sacl.Header.AceCount)
	}
}
