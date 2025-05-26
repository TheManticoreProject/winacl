package acl

import "github.com/TheManticoreProject/winacl/ace"

// AddEntry adds a new ACE entry to the DiscretionaryAccessControlList.
//
// Parameters:
//   - entry (ace.AccessControlEntry): The ACE entry to add.
func (dacl *DiscretionaryAccessControlList) AddEntry(entry ace.AccessControlEntry) {
	// Update the entry index
	entry.Index = uint16(len(dacl.Entries) + 1)

	// Add the entry to the list
	dacl.Entries = append(dacl.Entries, entry)

	// Update the header count
	dacl.Header.AceCount = uint16(len(dacl.Entries))
}

// RemoveEntry removes an ACE entry from the DiscretionaryAccessControlList.
//
// Parameters:
//   - ace (ace.AccessControlEntry): The ACE entry to remove.
//
// Returns:
//   - None
func (dacl *DiscretionaryAccessControlList) RemoveEntry(ace ace.AccessControlEntry) {
	for i, entry := range dacl.Entries {
		if entry.Equal(&ace) {
			dacl.Entries = append(dacl.Entries[:i], dacl.Entries[i+1:]...)
			dacl.Header.AceCount = uint16(len(dacl.Entries))
			return
		}
	}
}

// ClearEntries removes all ACE entries from the DiscretionaryAccessControlList.
//
// Returns:
//   - None
func (dacl *DiscretionaryAccessControlList) ClearEntries() {
	dacl.Entries = []ace.AccessControlEntry{}
	dacl.Header.AceCount = 0
}
