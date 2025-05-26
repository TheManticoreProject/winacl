package acl

import "github.com/TheManticoreProject/winacl/ace"

// AddEntry adds a new ACE entry to the SystemAccessControlList.
//
// Parameters:
//   - entry (ace.AccessControlEntry): The ACE entry to add.
func (sacl *SystemAccessControlList) AddEntry(entry ace.AccessControlEntry) {
	// Update the entry index
	entry.Index = uint16(len(sacl.Entries) + 1)

	// Add the entry to the list
	sacl.Entries = append(sacl.Entries, entry)

	// Update the header count
	sacl.Header.AceCount = uint16(len(sacl.Entries))
}

// RemoveEntry removes an ACE entry from the SystemAccessControlList.
//
// Parameters:
//   - ace (ace.AccessControlEntry): The ACE entry to remove.
//
// Returns:
//   - None
func (sacl *SystemAccessControlList) RemoveEntry(entry ace.AccessControlEntry) {
	newEntries := []ace.AccessControlEntry{}
	for _, existingEntry := range sacl.Entries {
		if !entry.Equal(&existingEntry) {
			newEntries = append(newEntries, existingEntry)
		}
	}

	sacl.Entries = newEntries
	sacl.Header.AceCount = uint16(len(sacl.Entries))
}

// ClearEntries removes all ACE entries from the SystemAccessControlList.
//
// Returns:
//   - None
func (sacl *SystemAccessControlList) ClearEntries() {
	sacl.Entries = []ace.AccessControlEntry{}
	sacl.Header.AceCount = 0
}
