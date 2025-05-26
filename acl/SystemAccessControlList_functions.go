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
func (sacl *SystemAccessControlList) RemoveEntry(ace ace.AccessControlEntry) {
	for i, entry := range sacl.Entries {
		if entry.Equal(&ace) {
			sacl.Entries = append(sacl.Entries[:i], sacl.Entries[i+1:]...)
			sacl.Header.AceCount = uint16(len(sacl.Entries))
			return
		}
	}
}

// ClearEntries removes all ACE entries from the SystemAccessControlList.
//
// Returns:
//   - None
func (sacl *SystemAccessControlList) ClearEntries() {
	sacl.Entries = []ace.AccessControlEntry{}
	sacl.Header.AceCount = 0
}
