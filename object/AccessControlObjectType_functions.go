package object

// Equal checks if two AccessControlObjectType objects are equal by comparing all their fields.
//
// Parameters:
// - other: The other AccessControlObjectType to compare with
//
// Returns:
// - bool: true if the AccessControlObjectTypes are equal, false otherwise
func (aco *AccessControlObjectType) Equal(other *AccessControlObjectType) bool {
	if aco == nil || other == nil {
		return aco == other
	}

	// Compare Flags
	if aco.Flags.Value != other.Flags.Value {
		return false
	}

	// Compare ObjectType if present
	if aco.Flags.IsObjectTypePresent() {
		if !aco.ObjectType.Equal(&other.ObjectType) {
			return false
		}
	}

	// Compare InheritedObjectType if present
	if aco.Flags.IsInheritedObjectTypePresent() {
		if !aco.InheritedObjectType.Equal(&other.InheritedObjectType) {
			return false
		}
	}

	return true
}
