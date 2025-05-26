package header

// Equal checks if two AccessControlEntryHeader objects are equal by comparing all their fields.
//
// Parameters:
// - other: The other AccessControlEntryHeader to compare with
//
// Returns:
// - bool: true if the AccessControlEntryHeaders are equal, false otherwise
func (header *AccessControlEntryHeader) Equal(other *AccessControlEntryHeader) bool {
	if header == nil || other == nil {
		return header == other
	}

	// Compare Size
	if header.Size != other.Size {
		return false
	}

	// Compare Type
	if header.Type != other.Type {
		return false
	}

	// Compare Flags
	if !header.Flags.Equal(&other.Flags) {
		return false
	}

	return true
}
