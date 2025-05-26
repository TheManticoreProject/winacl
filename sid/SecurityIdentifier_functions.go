package sid

// Equal checks if two SecurityIdentifier objects are equal by comparing all their fields.
//
// Parameters:
// - other: The other SecurityIdentifier to compare with
//
// Returns:
// - bool: true if the SecurityIdentifiers are equal, false otherwise
func (sid *SID) Equal(other *SID) bool {
	if sid == nil || other == nil {
		return sid == other
	}

	// Compare RevisionLevel
	if sid.RevisionLevel != other.RevisionLevel {
		return false
	}

	// Compare SubAuthorityCount
	if sid.SubAuthorityCount != other.SubAuthorityCount {
		return false
	}

	// Compare IdentifierAuthority
	if sid.IdentifierAuthority.Value != other.IdentifierAuthority.Value {
		return false
	}

	// Compare SubAuthorities
	if len(sid.SubAuthorities) != len(other.SubAuthorities) {
		return false
	}
	for i, subAuthority := range sid.SubAuthorities {
		if subAuthority != other.SubAuthorities[i] {
			return false
		}
	}

	// Compare RelativeIdentifier
	if sid.RelativeIdentifier != other.RelativeIdentifier {
		return false
	}

	// Compare Reserved
	if len(sid.Reserved) != len(other.Reserved) {
		return false
	}
	for i, reserved := range sid.Reserved {
		if reserved != other.Reserved[i] {
			return false
		}
	}

	return true
}
