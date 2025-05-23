package securitydescriptor

import (
	"encoding/binary"
)

// NtSecurityDescriptorControl represents the control flags for a NT Security Descriptor.
// The fields are defined as constants to represent their bit positions.
type NtSecurityDescriptorControl struct {
	RawValue uint16
	Values   []uint16
	Flags    []string
}

// Control indexes in bit field
const (
	NT_SECURITY_DESCRIPTOR_CONTROL_SR uint16 = 1 << iota // Self-Relative
	NT_SECURITY_DESCRIPTOR_CONTROL_RM                    // RM Control Valid
	NT_SECURITY_DESCRIPTOR_CONTROL_PS                    // SACL Protected
	NT_SECURITY_DESCRIPTOR_CONTROL_PD                    // DACL Protected
	NT_SECURITY_DESCRIPTOR_CONTROL_SI                    // SACL Auto-Inherited
	NT_SECURITY_DESCRIPTOR_CONTROL_DI                    // DACL Auto-Inherited
	NT_SECURITY_DESCRIPTOR_CONTROL_SC                    // SACL Computed Inheritance Required
	NT_SECURITY_DESCRIPTOR_CONTROL_DC                    // DACL Computed Inheritance Required
	NT_SECURITY_DESCRIPTOR_CONTROL_SS                    // Server Security
	NT_SECURITY_DESCRIPTOR_CONTROL_DT                    // DACL Trusted
	NT_SECURITY_DESCRIPTOR_CONTROL_SD                    // SACL Defaulted
	NT_SECURITY_DESCRIPTOR_CONTROL_SP                    // SACL Present
	NT_SECURITY_DESCRIPTOR_CONTROL_DD                    // DACL Defaulted
	NT_SECURITY_DESCRIPTOR_CONTROL_DP                    // DACL Present
	NT_SECURITY_DESCRIPTOR_CONTROL_GD                    // Group Defaulted
	NT_SECURITY_DESCRIPTOR_CONTROL_OD                    // Owner Defaulted
)

// Control flag map from value to string representation
var NtSecurityDescriptorControlValueToName = map[uint16]string{
	NT_SECURITY_DESCRIPTOR_CONTROL_SR: "Self-Relative",
	NT_SECURITY_DESCRIPTOR_CONTROL_RM: "RM Control Valid",
	NT_SECURITY_DESCRIPTOR_CONTROL_PS: "SACL Protected",
	NT_SECURITY_DESCRIPTOR_CONTROL_PD: "DACL Protected",
	NT_SECURITY_DESCRIPTOR_CONTROL_SI: "SACL Auto-Inherited",
	NT_SECURITY_DESCRIPTOR_CONTROL_DI: "DACL Auto-Inherited",
	NT_SECURITY_DESCRIPTOR_CONTROL_SC: "SACL Computed Inheritance Required",
	NT_SECURITY_DESCRIPTOR_CONTROL_DC: "DACL Computed Inheritance Required",
	NT_SECURITY_DESCRIPTOR_CONTROL_SS: "Server Security",
	NT_SECURITY_DESCRIPTOR_CONTROL_DT: "DACL Trusted",
	NT_SECURITY_DESCRIPTOR_CONTROL_SD: "SACL Defaulted",
	NT_SECURITY_DESCRIPTOR_CONTROL_SP: "SACL Present",
	NT_SECURITY_DESCRIPTOR_CONTROL_DD: "DACL Defaulted",
	NT_SECURITY_DESCRIPTOR_CONTROL_DP: "DACL Present",
	NT_SECURITY_DESCRIPTOR_CONTROL_GD: "Group Defaulted",
	NT_SECURITY_DESCRIPTOR_CONTROL_OD: "Owner Defaulted",
}

// Control flag map from value to string representation
var NtSecurityDescriptorControlValueToShortName = map[uint16]string{
	NT_SECURITY_DESCRIPTOR_CONTROL_SR: "SR",
	NT_SECURITY_DESCRIPTOR_CONTROL_RM: "RM",
	NT_SECURITY_DESCRIPTOR_CONTROL_PS: "PS",
	NT_SECURITY_DESCRIPTOR_CONTROL_PD: "PD",
	NT_SECURITY_DESCRIPTOR_CONTROL_SI: "SI",
	NT_SECURITY_DESCRIPTOR_CONTROL_DI: "DI",
	NT_SECURITY_DESCRIPTOR_CONTROL_SC: "SC",
	NT_SECURITY_DESCRIPTOR_CONTROL_DC: "DC",
	NT_SECURITY_DESCRIPTOR_CONTROL_SS: "SS",
	NT_SECURITY_DESCRIPTOR_CONTROL_DT: "DT",
	NT_SECURITY_DESCRIPTOR_CONTROL_SD: "SD",
	NT_SECURITY_DESCRIPTOR_CONTROL_SP: "SP",
	NT_SECURITY_DESCRIPTOR_CONTROL_DD: "DD",
	NT_SECURITY_DESCRIPTOR_CONTROL_DP: "DP",
	NT_SECURITY_DESCRIPTOR_CONTROL_GD: "GD",
	NT_SECURITY_DESCRIPTOR_CONTROL_OD: "OD",
}

// Unmarshal initializes the NtSecurityDescriptorControl struct by setting its RawValue
// and extracting the individual control flags from it. It populates the Values and Flags slices
// based on the control flags that are present in the RawValue.
//
// Parameters:
//   - rawValue (uint16): The raw value to be parsed, representing the control flags as a bitmask.
func (nsdc *NtSecurityDescriptorControl) Unmarshal(rawValue []byte) (int, error) {
	nsdc.RawValue = binary.LittleEndian.Uint16(rawValue)
	nsdc.Values = []uint16{}
	nsdc.Flags = []string{}

	for flagValue, flagName := range NtSecurityDescriptorControlValueToShortName {
		if (nsdc.RawValue & flagValue) == flagValue {
			nsdc.Values = append(nsdc.Values, flagValue)
			nsdc.Flags = append(nsdc.Flags, flagName)
		}
	}

	return 2, nil
}

// Marshal serializes the NtSecurityDescriptorControl struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the security descriptor control.
func (nsdc *NtSecurityDescriptorControl) Marshal() ([]byte, error) {
	serializedData := make([]byte, 2)
	binary.LittleEndian.PutUint16(serializedData, nsdc.RawValue)
	return serializedData, nil
}

// HasControl checks if a specific control bit is set in the RawValue.
// Parameters:
//   - control (uint16): The control flag to check (NT_SECURITY_DESCRIPTOR_CONTROL_*).
//
// Returns:
//   - bool: True if the specified control bit is set, false otherwise.
func (nsdc *NtSecurityDescriptorControl) HasControl(control uint16) bool {
	return (nsdc.RawValue & control) == control
}

// AddControl adds a specific control bit to the RawValue.
//
// Parameters:
//   - control (uint16): The control flag to add (NT_SECURITY_DESCRIPTOR_CONTROL_*).
//
// Returns:
//   - bool: True if the control was added, false if it was already present.
func (nsdc *NtSecurityDescriptorControl) AddControl(control uint16) bool {
	if nsdc.HasControl(control) {
		return false
	}

	nsdc.RawValue |= control

	// Update Values and Flags slices
	flagName, exists := NtSecurityDescriptorControlValueToShortName[control]
	if exists {
		nsdc.Values = append(nsdc.Values, control)
		nsdc.Flags = append(nsdc.Flags, flagName)
	}

	return true
}

// RemoveControl removes a specific control bit from the RawValue.
//
// Parameters:
//   - control (uint16): The control flag to remove (NT_SECURITY_DESCRIPTOR_CONTROL_*).
//
// Returns:
//   - bool: True if the control was removed, false if it was not present.
func (nsdc *NtSecurityDescriptorControl) RemoveControl(control uint16) bool {
	if !nsdc.HasControl(control) {
		return false
	}

	nsdc.RawValue &= ^control

	// Update Values and Flags slices
	for i, value := range nsdc.Values {
		if value == control {
			// Remove the value from the Values slice
			nsdc.Values = append(nsdc.Values[:i], nsdc.Values[i+1:]...)
			// Remove the corresponding flag from the Flags slice
			nsdc.Flags = append(nsdc.Flags[:i], nsdc.Flags[i+1:]...)
			break
		}
	}

	return true
}
