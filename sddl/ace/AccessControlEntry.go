package ace

import (
	"fmt"
	"strings"

	ntsd_ace "github.com/TheManticoreProject/winacl/ace"
)

// ParseSDDLAceString parses an SDDL ACE string into an NT Security Descriptor ACE.
//
// The SDDL ACE string format is: aceType;aceFlags;rights;objectGuid;inheritedObjectGuid;accountSid
// Example: "A;OICI;GA;;;BA"
//
// Parameters:
//   - aceString (string): The SDDL ACE string to parse
//
// Returns:
//   - (*ntsd_ace.AccessControlEntry, error): The parsed ACE and any error that occurred
func ParseSDDLAceString(aceString string) (*ntsd_ace.AccessControlEntry, error) {
	// Split the ACE string into components
	parts := strings.Split(aceString, ";")
	if len(parts) < 6 {
		return nil, fmt.Errorf("invalid ACE string format: %s", aceString)
	}

	aceType := parts[0]
	aceFlags := parts[1]
	rights := parts[2]
	objectGuid := parts[3]
	inheritedObjectGuid := parts[4]
	accountSid := parts[5]

	// Create new ACE
	ace := &ntsd_ace.AccessControlEntry{
		Header: ntsd_ace.AccessControlEntryHeader{
			Type: SDDLToACETypeMap[aceType],
			// TODO: Parse ACE flags
			// TODO: Calculate ACE size
		},
		// TODO: Parse rights into Mask
		// TODO: Parse object GUID if present
		// TODO: Parse inherited object GUID if present
		// TODO: Parse account SID
	}

	return ace, nil
}
