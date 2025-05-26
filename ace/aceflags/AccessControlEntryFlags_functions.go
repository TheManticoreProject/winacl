package aceflags

// Equal checks if two AccessControlEntryFlag objects are equal by comparing all their fields.
//
// Parameters:
// - other: The other AccessControlEntryFlag to compare with
//
// Returns:
// - bool: true if the AccessControlEntryFlag are equal, false otherwise
func (aceflag *AccessControlEntryFlag) Equal(other *AccessControlEntryFlag) bool {
	if aceflag == nil || other == nil {
		return aceflag == other
	}

	// Compare RawValue
	if aceflag.RawValue != other.RawValue {
		return false
	}

	// Compare Values
	if len(aceflag.Values) != len(other.Values) {
		return false
	}
	for i, value := range aceflag.Values {
		if value != other.Values[i] {
			return false
		}
	}

	return true
}
