package sddl

import (
	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

// SDDLtoNtSecurityDescriptor converts an SDDL string to an NtSecurityDescriptor.
//
// Parameters:
//   - sddlString (string): The SDDL string to convert.
//
// Returns:
//   - (*securitydescriptor.NtSecurityDescriptor, error): The converted security descriptor and any error that occurred.
func SDDLtoNtSecurityDescriptor(sddlString string) (*securitydescriptor.NtSecurityDescriptor, error) {
	ntsd := &securitydescriptor.NtSecurityDescriptor{}

	// ownerSid, groupSid, daclAces, saclAces := sddlCut(sddlString)

	// Unmarshal the Owner

	// Unmarshal the Group

	// Unmarshal the DACL

	// Unmarshal the SACL

	return ntsd, nil
}

// NtSecurityDescriptortoSDDL converts an NtSecurityDescriptor to an SDDL string.
//
// Parameters:
//   - ntsd (*securitydescriptor.NtSecurityDescriptor): The security descriptor to convert.
//
// Returns:
//   - (string, error): The SDDL string representation and any error that occurred.
func NtSecurityDescriptortoSDDL(ntsd *securitydescriptor.NtSecurityDescriptor) (string, error) {
	sddlString := ""

	// Marshal the Owner

	// Marshal the Group

	// Marshal the DACL

	// Marshal the SACL

	return sddlString, nil
}
