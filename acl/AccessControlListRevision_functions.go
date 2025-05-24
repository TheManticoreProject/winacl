package acl

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
