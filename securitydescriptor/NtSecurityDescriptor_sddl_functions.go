package securitydescriptor

// FromSDDLString converts an SDDL string to an NtSecurityDescriptor.
//
// Parameters:
//   - sddlString (string): The SDDL string to convert.
//
// Returns:
//   - error: An error if parsing fails, otherwise nil.
func (ntsd *NtSecurityDescriptor) FromSDDLString(sddlString string) error {
	return nil
}

// ToSDDLString converts an NtSecurityDescriptor to an SDDL string.
//
// Parameters:
//   - ntsd (*NtSecurityDescriptor): The security descriptor to convert.
//
// Returns:
//   - (string, error): The SDDL string representation and any error that occurred.
func (ntsd *NtSecurityDescriptor) ToSDDLString() (string, error) {
	return "", nil
}
