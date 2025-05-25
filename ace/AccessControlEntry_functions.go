package ace

import "slices"

// IsInherited checks whether the Access Control Entry (ACE) is inherited
// from a parent object. This is determined by checking if the ACE_FLAG_INHERITED
// is present in the Flags.Values slice of the ACE header.
//
// Returns:
// - bool: true if the ACE is inherited, false otherwise.
func (ace *AccessControlEntry) IsInherited() bool {
	return slices.Contains(ace.Header.Flags.Values, ACE_FLAG_INHERITED)
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
