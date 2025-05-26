package ace

import (
	"slices"

	"github.com/TheManticoreProject/winacl/ace/aceflags"
)

// IsInherited checks whether the Access Control Entry (ACE) is inherited
// from a parent object. This is determined by checking if the ACE_FLAG_INHERITED
// is present in the Flags.Values slice of the ACE header.
//
// Returns:
// - bool: true if the ACE is inherited, false otherwise.
func (ace *AccessControlEntry) IsInherited() bool {
	return slices.Contains(ace.Header.Flags.Values, aceflags.ACE_FLAG_INHERITED)
}

// HasFlag checks if a specific flag is set within the ACE's flags.
//
// Parameters:
// - flag: The integer value of the flag to check.
//
// Returns:
// - bool: true if the specified flag is set, false otherwise.
func (ace *AccessControlEntry) HasFlag(flag uint8) bool {
	return slices.Contains(ace.Header.Flags.Values, flag)
}

// Equal checks if two AccessControlEntry objects are equal by comparing all their fields.
//
// Parameters:
// - other: The other AccessControlEntry to compare with
//
// Returns:
// - bool: true if the AccessControlEntries are equal, false otherwise
func (ace *AccessControlEntry) Equal(other *AccessControlEntry) bool {
	if ace == nil || other == nil {
		return ace == other
	}

	// Compare Header
	if !ace.Header.Equal(&other.Header) {
		return false
	}

	// Compare Mask
	if !ace.Mask.Equal(&other.Mask) {
		return false
	}

	// Compare Identity
	if !ace.Identity.Equal(&other.Identity) {
		return false
	}

	// Compare ObjectType fields if present
	if !ace.AccessControlObjectType.Equal(&other.AccessControlObjectType) {
		return false
	}

	return true
}
