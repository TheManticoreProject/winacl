package sddl

import (
	"fmt"

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
	_ = sddlString
	return nil, fmt.Errorf("SDDLtoNtSecurityDescriptor is not yet implemented")
}

// NtSecurityDescriptortoSDDL converts an NtSecurityDescriptor to an SDDL string.
//
// Parameters:
//   - ntsd (*securitydescriptor.NtSecurityDescriptor): The security descriptor to convert.
//
// Returns:
//   - (string, error): The SDDL string representation and any error that occurred.
func NtSecurityDescriptortoSDDL(ntsd *securitydescriptor.NtSecurityDescriptor) (string, error) {
	_ = ntsd
	return "", fmt.Errorf("NtSecurityDescriptortoSDDL is not yet implemented")
}
