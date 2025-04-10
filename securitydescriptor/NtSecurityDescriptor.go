package securitydescriptor

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/TheManticoreProject/winacl/acl"
	"github.com/TheManticoreProject/winacl/identity"
)

// NtSecurityDescriptor represents a Windows security descriptor.
type NtSecurityDescriptor struct {
	Header NtSecurityDescriptorHeader

	Owner identity.Identity
	Group identity.Identity

	DACL acl.DiscretionaryAccessControlList
	SACL acl.SystemAccessControlList

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Parse initializes the NtSecurityDescriptor struct by parsing the raw byte array.
//
// Parameters:
//   - rawBytes ([]byte): The raw byte array to be parsed.
//
// Returns:
//   - error: An error if parsing fails, otherwise nil.
func (ntsd *NtSecurityDescriptor) Parse(rawBytes []byte) error {
	debug := false

	ntsd.RawBytes = rawBytes
	ntsd.RawBytesSize = 0

	// Parse the header
	if debug {
		fmt.Printf("[debug][NtSecurityDescriptor.Parse()] rawBytes: %s\n", hex.EncodeToString(ntsd.RawBytes))
	}
	ntsd.Header.Parse(ntsd.RawBytes)
	ntsd.RawBytesSize += ntsd.Header.RawBytesSize

	// Parse Owner if present
	if ntsd.Header.OffsetOwner != 0 {
		if debug {
			fmt.Printf("[debug][NtSecurityDescriptor.Parse()] rawBytes[ntsd.Header.OffsetOwner:]: %s\n", hex.EncodeToString(ntsd.RawBytes[ntsd.Header.OffsetOwner:]))
		}
		ntsd.Owner.Parse(ntsd.RawBytes[ntsd.Header.OffsetOwner:])
		ntsd.RawBytesSize += ntsd.Owner.SID.RawBytesSize
	}

	// Parse Group if present
	if ntsd.Header.OffsetGroup != 0 {
		if debug {
			fmt.Printf("[debug][NtSecurityDescriptor.Parse()] rawBytes[ntsd.Header.OffsetGroup:]: %s\n", hex.EncodeToString(ntsd.RawBytes[ntsd.Header.OffsetGroup:]))
		}
		ntsd.Group.Parse(ntsd.RawBytes[ntsd.Header.OffsetGroup:])
		ntsd.RawBytesSize += ntsd.Group.SID.RawBytesSize
	}

	// Parse DACL if present
	if ntsd.Header.OffsetDacl != 0 {
		if debug {
			fmt.Printf("[debug][NtSecurityDescriptor.Parse()] rawBytes[ntsd.Header.OffsetDacl:]: %s\n", hex.EncodeToString(ntsd.RawBytes[ntsd.Header.OffsetDacl:]))
		}
		ntsd.DACL.Parse(ntsd.RawBytes[ntsd.Header.OffsetDacl:])
		ntsd.RawBytesSize += ntsd.DACL.RawBytesSize
	}

	// Parse SACL if present
	if ntsd.Header.OffsetSacl != 0 {
		if debug {
			fmt.Printf("[debug][NtSecurityDescriptor.Parse()] rawBytes[ntsd.Header.OffsetSacl:]: %s\n", hex.EncodeToString(ntsd.RawBytes[ntsd.Header.OffsetSacl:]))
		}
		ntsd.SACL.Parse(ntsd.RawBytes[ntsd.Header.OffsetSacl:])
		ntsd.RawBytesSize += ntsd.SACL.RawBytesSize
	}

	return nil
}

func (ntsd *NtSecurityDescriptor) ToBytes() []byte {
	// Initialize a byte slice to hold the serialized data
	var serializedData []byte

	dataSacl := ntsd.SACL.ToBytes()
	offsetSacl := 20 // (0x00000014)
	dataDacl := ntsd.DACL.ToBytes()
	offsetDacl := offsetSacl + len(dataSacl)
	dataOwner := ntsd.Owner.SID.ToBytes()
	offsetOwner := offsetSacl + len(dataSacl) + len(dataDacl)
	dataGroup := ntsd.Group.SID.ToBytes()
	offsetGroup := offsetSacl + len(dataSacl) + len(dataDacl) + len(dataOwner)

	// Update the header and append the header bytes
	ntsd.Header.OffsetOwner = uint32(offsetOwner)
	ntsd.Header.OffsetGroup = uint32(offsetGroup)
	ntsd.Header.OffsetSacl = uint32(offsetSacl)
	ntsd.Header.OffsetDacl = uint32(offsetDacl)
	serializedData = append(serializedData, ntsd.Header.ToBytes()...)

	// Append the SACL bytes if present
	if ntsd.Header.OffsetSacl != 0 {
		serializedData = append(serializedData, dataSacl...)
	}
	// Append the DACL bytes if present
	if ntsd.Header.OffsetDacl != 0 {
		serializedData = append(serializedData, dataDacl...)
	}
	// Append the Owner SID bytes if present
	if ntsd.Header.OffsetOwner != 0 {
		serializedData = append(serializedData, dataOwner...)
	}
	// Append the Group SID bytes if present
	if ntsd.Header.OffsetGroup != 0 {
		serializedData = append(serializedData, dataGroup...)
	}

	return serializedData
}

// Describe prints the NtSecurityDescriptor in a human-readable format.
//
// Parameters:
//   - indent (int): The indentation level for the output.
func (ntsd *NtSecurityDescriptor) Describe(indent int) {
	fmt.Println("<NTSecurityDescriptor>")

	ntsd.Header.Describe(indent + 1)

	if ntsd.Header.OffsetOwner != 0 {
		fmt.Printf("%s<Owner>\n", strings.Repeat(" │ ", indent+1))
		ntsd.Owner.Describe(indent + 2)
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	}

	if ntsd.Header.OffsetGroup != 0 {
		fmt.Printf("%s<Group>\n", strings.Repeat(" │ ", indent+1))
		ntsd.Group.Describe(indent + 2)
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	}

	if ntsd.Header.OffsetSacl > ntsd.Header.OffsetDacl {
		// Print DACL
		if ntsd.Header.OffsetDacl != 0 {
			ntsd.DACL.Describe(indent + 1)
		} else {
			fmt.Printf("%s<DiscretionaryAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
			fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
		}

		// Print SACL
		if ntsd.Header.OffsetSacl != 0 {
			ntsd.SACL.Describe(indent + 1)
		} else {
			fmt.Printf("%s<SystemAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
			fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
		}
	} else {
		// Print SACL
		if ntsd.Header.OffsetSacl != 0 {
			ntsd.SACL.Describe(indent + 1)
		} else {
			fmt.Printf("%s<SystemAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
			fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
		}

		// Print DACL
		if ntsd.Header.OffsetDacl != 0 {
			ntsd.DACL.Describe(indent + 1)
		} else {
			fmt.Printf("%s<DiscretionaryAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
			fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
		}
	}

	fmt.Println(" └─")
}

// Methods ========================================================================

// FindIdentitiesWithExtendedRight finds identities that have a specific extended right.
//
// Parameters:
//   - extendedRightGUID (string): The GUID of the extended right to search for.
//
// Returns:
//   - map[*identity.SID][]string: A map of identities to their matching extended rights.
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithExtendedRight(extendedRightGUID string) map[*identity.SID][]string {
	identitiesMap := make(map[*identity.SID][]string)

	for _, ace := range ntsd.DACL.Entries {
		matchingRights := make([]string, 0)
		if strings.EqualFold(ace.AccessControlObjectType.ObjectType.GUID.ToFormatD(), extendedRightGUID) {
			matchingRights = append(matchingRights, extendedRightGUID)
			identitiesMap[&ace.SID.SID] = matchingRights
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
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithAnyExtendedRight(extendedRightsGUIDs []string) map[*identity.SID][]string {
	identitiesMap := make(map[*identity.SID][]string)

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
			identitiesMap[&ace.SID.SID] = matchingRights
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
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithAllExtendedRights(extendedRightsGUIDs []string) map[*identity.SID][]string {
	identitiesMap := make(map[*identity.SID][]string)

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
			identitiesMap[&ace.SID.SID] = extendedRightsGUIDs
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
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithRight(accessMaskRightValue uint32) map[*identity.SID][]uint32 {
	identitiesMap := make(map[*identity.SID][]uint32)

	for _, ace := range ntsd.DACL.Entries {
		matchingRights := make([]uint32, 0)
		if slices.Contains(ace.Mask.Values, accessMaskRightValue) {
			matchingRights = append(matchingRights, accessMaskRightValue)
			identitiesMap[&ace.SID.SID] = matchingRights
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
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithAnyRight(accessMaskRights []uint32) map[*identity.SID][]uint32 {
	identitiesMap := make(map[*identity.SID][]uint32)

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
			identitiesMap[&ace.SID.SID] = matchingRights
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
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithAllRights(accessMaskRights []uint32) map[*identity.SID][]uint32 {
	identitiesMap := make(map[*identity.SID][]uint32)

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
			identitiesMap[&ace.SID.SID] = accessMaskRights
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
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithUnexpectedRights(expectedRightsToIdentitiesMap map[uint32][]string) map[uint32][]*identity.SID {
	unexpectedIdentities := map[uint32][]*identity.SID{}

	for specificRight, expectedIdentities := range expectedRightsToIdentitiesMap {

		for id := range ntsd.FindIdentitiesWithRight(specificRight) {
			if !slices.Contains(expectedIdentities, id.ToString()) {
				if _, ok := unexpectedIdentities[specificRight]; !ok {
					unexpectedIdentities[specificRight] = make([]*identity.SID, 0)
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
func (ntsd *NtSecurityDescriptor) FindIdentitiesWithUnexpectedExtendedRights(expectedExtendedRightsToIdentitiesMap map[string][]string) map[string][]*identity.SID {
	unexpectedIdentities := map[string][]*identity.SID{}

	for specificExtendedRightGUID, expectedIdentities := range expectedExtendedRightsToIdentitiesMap {

		for id := range ntsd.FindIdentitiesWithExtendedRight(specificExtendedRightGUID) {
			if !slices.Contains(expectedIdentities, id.ToString()) {
				if _, ok := unexpectedIdentities[specificExtendedRightGUID]; !ok {
					unexpectedIdentities[specificExtendedRightGUID] = make([]*identity.SID, 0)
				}
				unexpectedIdentities[specificExtendedRightGUID] = append(unexpectedIdentities[specificExtendedRightGUID], id)
			}
		}
	}

	return unexpectedIdentities
}
