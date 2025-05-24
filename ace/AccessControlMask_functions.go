package ace

import (
	"slices"
	"sort"

	"github.com/TheManticoreProject/winacl/rights"
)

// HasRight checks if a specific right is set within the ACE's Mask.
//
// Parameters:
// - right: The integer value of the right to check.
//
// Returns:
// - bool: true if the specified right is set, false otherwise.
func (acm *AccessControlMask) HasRight(right uint32) bool {
	return slices.Contains(acm.Values, right)
}

// AddRight adds a specific right to the ACE's Mask.
//
// Parameters:
// - right: The integer value of the right to add.
func (acm *AccessControlMask) AddRight(right uint32) {
	// Only add if not already present
	if !acm.HasRight(right) {
		acm.RawValue |= right
		acm.Values = append(acm.Values, right)
		if rightName, ok := rights.RightValueToRightName[right]; ok {
			acm.Flags = append(acm.Flags, rightName)
			// Keep flags sorted for consistent output
			sort.Strings(acm.Flags)
		}
	}
}

// RemoveRight removes a specific right from the ACE's Mask.
//
// Parameters:
// - right: The integer value of the right to remove.
func (acm *AccessControlMask) RemoveRight(right uint32) {
	if acm.HasRight(right) {
		acm.RawValue &^= right
		// Remove from Values slice
		for i, v := range acm.Values {
			if v == right {
				acm.Values = append(acm.Values[:i], acm.Values[i+1:]...)
				break
			}
		}
		// Remove from Flags slice if name exists
		if rightName, ok := rights.RightValueToRightName[right]; ok {
			for i, f := range acm.Flags {
				if f == rightName {
					acm.Flags = append(acm.Flags[:i], acm.Flags[i+1:]...)
					break
				}
			}
		}
	}
}

// ClearRights removes all rights from the ACE's Mask.
func (acm *AccessControlMask) ClearRights() {
	acm.RawValue = 0
	acm.Values = make([]uint32, 0)
	acm.Flags = make([]string, 0)
}

// SetRights sets the ACE's Mask to exactly match the provided rights.
//
// Parameters:
// - rights: Slice of integer values representing the rights to set.
func (acm *AccessControlMask) SetRights(rights []uint32) {
	acm.ClearRights()
	for _, right := range rights {
		acm.AddRight(right)
	}
}
