package identity

// Equal checks if two Identity objects are equal by comparing all their fields.
//
// Parameters:
// - other: The other Identity to compare with
//
// Returns:
// - bool: true if the Identities are equal, false otherwise
func (identity *Identity) Equal(other *Identity) bool {
	if identity == nil || other == nil {
		return identity == other
	}

	// Compare Name
	if identity.Name != other.Name {
		return false
	}

	// Compare SID
	if !identity.SID.Equal(&other.SID) {
		return false
	}

	return true
}
