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
