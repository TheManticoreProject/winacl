package revision

// GetRevision returns the revision of the Access Control List.
//
// Returns:
//   - uint8: The revision of the Access Control List.
func (aclrev *AccessControlListRevision) GetRevision() uint8 {
	return aclrev.Value
}

// SetRevision sets the revision of the Access Control List.
//
// Parameters:
//   - revision: The revision to set.
func (aclrev *AccessControlListRevision) SetRevision(revision uint8) {
	aclrev.Value = revision
}

// Equal checks if two AccessControlListRevision structs are equal.
//
// Parameters:
//   - other: The other AccessControlListRevision to compare with.
//
// Returns:
//   - bool: True if the revisions are equal, false otherwise.
func (aclrev *AccessControlListRevision) Equal(other *AccessControlListRevision) bool {
	if other == nil {
		return false
	}
	return aclrev.Value == other.Value
}
