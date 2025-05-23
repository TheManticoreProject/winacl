package acl_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
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
