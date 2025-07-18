package securitydescriptor

import (
	"slices"
	"strings"

	"github.com/TheManticoreProject/winacl/acl"
	"github.com/TheManticoreProject/winacl/acl/revision"
	"github.com/TheManticoreProject/winacl/identity"
	"github.com/TheManticoreProject/winacl/sid"
)

// FindIdentitiesWithExtendedRight finds identities that have a specific extended right.
//
// Parameters:
//   - extendedRightGUID (string): The GUID of the extended right to search for.
//
// Returns:
//   - map[*identity.SID][]string: A map of identities to their matching extended rights.
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithExtendedRight(extendedRightGUID string) map[*sid.SID][]string {
	identitiesMap := make(map[*sid.SID][]string)

	for _, ace := range ntsd.DACL.Entries {
		matchingRights := make([]string, 0)
		if strings.EqualFold(ace.AccessControlObjectType.ObjectType.GUID.ToFormatD(), extendedRightGUID) {
			matchingRights = append(matchingRights, extendedRightGUID)
			identitiesMap[&ace.Identity.SID] = matchingRights
		}
	}

	return identitiesMap
}

// FindIdentitiesWithAnyExtendedRight finds identities that have any of the specified extended rights.
//
// Parameters:
//   - extendedRightsGUIDs ([]string): The GUIDs of the extended rights to search for.
//
// Returns:
//   - map[*identity.SID][]string: A map of identities to their matching extended rights.
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithAnyExtendedRight(extendedRightsGUIDs []string) map[*sid.SID][]string {
	identitiesMap := make(map[*sid.SID][]string)

	if len(extendedRightsGUIDs) == 0 {
		return identitiesMap
	}

	for _, ace := range ntsd.DACL.Entries {
		matchingRights := make([]string, 0)
		for _, extendedRightGUID := range extendedRightsGUIDs {
			if strings.EqualFold(ace.AccessControlObjectType.ObjectType.GUID.ToFormatD(), extendedRightGUID) {
				matchingRights = append(matchingRights, extendedRightGUID)
			}
		}
		if len(matchingRights) != 0 {
			identitiesMap[&ace.Identity.SID] = matchingRights
		}
	}

	return identitiesMap
}

// FindIdentitiesWithAllExtendedRights finds identities that have all of the specified extended rights.
//
// Parameters:
//   - extendedRightsGUIDs ([]string): The GUIDs of the extended rights to search for.
//
// Returns:
//   - map[*identity.SID][]string: A map of identities to their matching extended rights.
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithAllExtendedRights(extendedRightsGUIDs []string) map[*sid.SID][]string {
	identitiesMap := make(map[*sid.SID][]string)

	if len(extendedRightsGUIDs) == 0 {
		return identitiesMap
	}

	for _, ace := range ntsd.DACL.Entries {
		allRightsMatched := true
		// fmt.Printf("ACE ID %d\n", ace.Index)
		for _, extendedRightGUID := range extendedRightsGUIDs {
			if strings.EqualFold(ace.AccessControlObjectType.ObjectType.GUID.ToFormatD(), extendedRightGUID) {
				// Right is present
				allRightsMatched = allRightsMatched && true
			} else {
				// Right is not present, skipping this identity
				allRightsMatched = allRightsMatched && false
				// fmt.Printf("break\n")
				break
			}
		}
		if allRightsMatched {
			identitiesMap[&ace.Identity.SID] = extendedRightsGUIDs
		}
	}

	return identitiesMap
}

// FindIdentitiesWithRight finds identities that have a specific access mask right.
//
// Parameters:
//   - accessMaskRightValue (uint32): The access mask right value to search for.
//
// Returns:
//   - map[*identity.SID][]uint32: A map of identities to their matching access mask rights.
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithRight(accessMaskRightValue uint32) map[*sid.SID][]uint32 {
	identitiesMap := make(map[*sid.SID][]uint32)

	for _, ace := range ntsd.DACL.Entries {
		matchingRights := make([]uint32, 0)
		if slices.Contains(ace.Mask.Values, accessMaskRightValue) {
			matchingRights = append(matchingRights, accessMaskRightValue)
			identitiesMap[&ace.Identity.SID] = matchingRights
		}
	}

	return identitiesMap
}

// FindIdentitiesWithAnyRight finds identities that have any of the specified access mask rights.
//
// Parameters:
//   - accessMaskRights ([]uint32): The access mask rights to search for.
//
// Returns:
//   - map[*identity.SID][]uint32: A map of identities to their matching access mask rights.
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithAnyRight(accessMaskRights []uint32) map[*sid.SID][]uint32 {
	identitiesMap := make(map[*sid.SID][]uint32)

	if len(accessMaskRights) == 0 {
		return identitiesMap
	}

	for _, ace := range ntsd.DACL.Entries {
		matchingRights := make([]uint32, 0)
		for _, accessMaskRightValue := range accessMaskRights {
			if slices.Contains(ace.Mask.Values, accessMaskRightValue) {
				matchingRights = append(matchingRights, accessMaskRightValue)
			}
		}
		if len(matchingRights) != 0 {
			identitiesMap[&ace.Identity.SID] = matchingRights
		}
	}

	return identitiesMap
}

// FindIdentitiesWithAllRights finds identities that have all of the specified access mask rights.
//
// Parameters:
//   - accessMaskRights ([]uint32): The access mask rights to search for.
//
// Returns:
//   - map[*identity.SID][]uint32: A map of identities to their matching access mask rights.
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithAllRights(accessMaskRights []uint32) map[*sid.SID][]uint32 {
	identitiesMap := make(map[*sid.SID][]uint32)

	if len(accessMaskRights) == 0 {
		return identitiesMap
	}

	for _, ace := range ntsd.DACL.Entries {
		allRightsMatched := true
		// fmt.Printf("ACE ID %d\n", ace.Index)
		for _, accessMaskRightValue := range accessMaskRights {
			if slices.Contains(ace.Mask.Values, accessMaskRightValue) {
				// Right is present
				allRightsMatched = allRightsMatched && true
			} else {
				// Right is not present, skipping this identity
				allRightsMatched = allRightsMatched && false
				// fmt.Printf("break\n")
				break
			}
		}
		if allRightsMatched {
			identitiesMap[&ace.Identity.SID] = accessMaskRights
		}
	}

	return identitiesMap
}

// FindIdentitiesWithUnexpectedRights finds identities that have unexpected access mask rights.
//
// Parameters:
//   - expectedRightsToIdentitiesMap (map[uint32][]string): A map of expected access mask rights to their corresponding identities.
//
// Returns:
//   - map[uint32][]*identity.SID: A map of unexpected access mask rights to their corresponding identities.
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithUnexpectedRights(expectedRightsToIdentitiesMap map[uint32][]string) map[uint32][]*sid.SID {
	unexpectedIdentities := map[uint32][]*sid.SID{}

	for specificRight, expectedIdentities := range expectedRightsToIdentitiesMap {

		for id := range ntsd.FindIdentitiesWithRight(specificRight) {
			if !slices.Contains(expectedIdentities, id.ToString()) {
				if _, ok := unexpectedIdentities[specificRight]; !ok {
					unexpectedIdentities[specificRight] = make([]*sid.SID, 0)
				}
				unexpectedIdentities[specificRight] = append(unexpectedIdentities[specificRight], id)
			}
		}
	}

	return unexpectedIdentities
}

// FindIdentitiesWithUnexpectedExtendedRights finds identities that have unexpected extended rights.
//
// Parameters:
//   - expectedExtendedRightsToIdentitiesMap (map[string][]string): A map of expected extended rights to their corresponding identities.
//
// Returns:
//   - map[string][]*identity.SID: A map of unexpected extended rights to their corresponding identities.
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithUnexpectedExtendedRights(expectedExtendedRightsToIdentitiesMap map[string][]string) map[string][]*sid.SID {
	unexpectedIdentities := map[string][]*sid.SID{}

	for specificExtendedRightGUID, expectedIdentities := range expectedExtendedRightsToIdentitiesMap {

		for id := range ntsd.FindIdentitiesWithExtendedRight(specificExtendedRightGUID) {
			if !slices.Contains(expectedIdentities, id.ToString()) {
				if _, ok := unexpectedIdentities[specificExtendedRightGUID]; !ok {
					unexpectedIdentities[specificExtendedRightGUID] = make([]*sid.SID, 0)
				}
				unexpectedIdentities[specificExtendedRightGUID] = append(unexpectedIdentities[specificExtendedRightGUID], id)
			}
		}
	}

	return unexpectedIdentities
}

// GetOwner returns the Owner field of the NtSecurityDescriptor.
//
// Returns:
//   - identity.Identity: The Owner field of the NtSecurityDescriptor.
func (ntsd *NtSecurityDescriptor) GetOwner() *identity.Identity {
	return ntsd.Owner
}

// SetOwner sets the Owner field of the NtSecurityDescriptor.
//
// Parameters:
//   - owner (identity.Identity): The new Owner field of the NtSecurityDescriptor.
func (ntsd *NtSecurityDescriptor) SetOwner(owner *identity.Identity) {
	ntsd.Owner = owner
}

// GetGroup returns the Group field of the NtSecurityDescriptor.
//
// Returns:
//   - identity.Identity: The Group field of the NtSecurityDescriptor.
func (ntsd *NtSecurityDescriptor) GetGroup() *identity.Identity {
	return ntsd.Group
}

// SetGroup sets the Group field of the NtSecurityDescriptor.
//
// Parameters:
//   - group (identity.Identity): The new Group field of the NtSecurityDescriptor.
func (ntsd *NtSecurityDescriptor) SetGroup(group *identity.Identity) {
	ntsd.Group = group
}

// GetDacl returns the DACL field of the NtSecurityDescriptor.
//
// Returns:
//   - acl.DiscretionaryAccessControlList: The DACL field of the NtSecurityDescriptor.
func (ntsd *NtSecurityDescriptor) GetDacl() *acl.DiscretionaryAccessControlList {
	return ntsd.DACL
}

// SetDacl sets the DACL field of the NtSecurityDescriptor.
//
// Parameters:
//   - dacl (acl.DiscretionaryAccessControlList): The new DACL field of the NtSecurityDescriptor.
func (ntsd *NtSecurityDescriptor) SetDacl(dacl *acl.DiscretionaryAccessControlList) {
	ntsd.DACL = dacl
}

// GetSacl returns the SACL field of the NtSecurityDescriptor.
//
// Returns:
//   - acl.SystemAccessControlList: The SACL field of the NtSecurityDescriptor.
func (ntsd *NtSecurityDescriptor) GetSacl() *acl.SystemAccessControlList {
	return ntsd.SACL
}

// SetSacl sets the SACL field of the NtSecurityDescriptor.
//
// Parameters:
//   - sacl (acl.SystemAccessControlList): The new SACL field of the NtSecurityDescriptor.
func (ntsd *NtSecurityDescriptor) SetSacl(sacl *acl.SystemAccessControlList) {
	ntsd.SACL = sacl
}

// Equal compares two NtSecurityDescriptor instances for equality.
//
// Parameters:
//   - other (*NtSecurityDescriptor): The NtSecurityDescriptor to compare with.
//
// Returns:
//   - bool: True if the NtSecurityDescriptors are equal, false otherwise.
func (ntsd *NtSecurityDescriptor) Equal(other *NtSecurityDescriptor) bool {
	if ntsd == nil || other == nil {
		return ntsd == other
	}

	// Compare headers
	if !ntsd.Header.Equal(&other.Header) {
		return false
	}

	// Compare Owner SIDs
	if ntsd.Owner != nil && other.Owner != nil {
		if !ntsd.Owner.SID.Equal(&other.Owner.SID) {
			return false
		}
	} else if ntsd.Owner != other.Owner {
		return false
	}

	// Compare Group SIDs
	if ntsd.Group != nil && other.Group != nil {
		if !ntsd.Group.SID.Equal(&other.Group.SID) {
			return false
		}
	} else if ntsd.Group != other.Group {
		return false
	}

	// Compare DACLs
	if ntsd.DACL != nil && other.DACL != nil {
		if len(ntsd.DACL.Entries) != len(other.DACL.Entries) {
			return false
		}
		for i := range ntsd.DACL.Entries {
			if !ntsd.DACL.Entries[i].Equal(&other.DACL.Entries[i]) {
				return false
			}
		}
	} else if ntsd.DACL != other.DACL {
		return false
	}

	// Compare SACLs
	if ntsd.SACL != nil && other.SACL != nil {
		if len(ntsd.SACL.Entries) != len(other.SACL.Entries) {
			return false
		}
		for i := range ntsd.SACL.Entries {
			if !ntsd.SACL.Entries[i].Equal(&other.SACL.Entries[i]) {
				return false
			}
		}
	} else if ntsd.SACL != other.SACL {
		return false
	}

	return true
}

// NewSecurityDescriptor creates a new NtSecurityDescriptor with initialized fields.
//
// Returns:
//   - *NtSecurityDescriptor: A pointer to the newly created security descriptor.
func NewSecurityDescriptor() *NtSecurityDescriptor {
	ntsd := &NtSecurityDescriptor{
		Owner: &identity.Identity{},

		Group: &identity.Identity{},

		DACL: &acl.DiscretionaryAccessControlList{},

		SACL: &acl.SystemAccessControlList{},
	}

	ntsd.Header.Revision = 0x01

	ntsd.DACL.Header.Revision.SetRevision(revision.ACL_REVISION_DS)
	ntsd.DACL.Header.AceCount = 0

	ntsd.SACL.Header.Revision.SetRevision(revision.ACL_REVISION_DS)
	ntsd.SACL.Header.AceCount = 0

	return ntsd
}
