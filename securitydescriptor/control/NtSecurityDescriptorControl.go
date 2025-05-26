package control

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
	NT_SECURITY_DESCRIPTOR_CONTROL_SR uint16 = 0x0001 // Self-Relative
	NT_SECURITY_DESCRIPTOR_CONTROL_RM uint16 = 0x0002 // RM Control Valid
	NT_SECURITY_DESCRIPTOR_CONTROL_PS uint16 = 0x0004 // SACL Protected
	NT_SECURITY_DESCRIPTOR_CONTROL_PD uint16 = 0x0008 // DACL Protected
	NT_SECURITY_DESCRIPTOR_CONTROL_SI uint16 = 0x0010 // SACL Auto-Inherited
	NT_SECURITY_DESCRIPTOR_CONTROL_DI uint16 = 0x0020 // DACL Auto-Inherited
	NT_SECURITY_DESCRIPTOR_CONTROL_SC uint16 = 0x0040 // SACL Computed Inheritance Required
	NT_SECURITY_DESCRIPTOR_CONTROL_DC uint16 = 0x0080 // DACL Computed Inheritance Required
	NT_SECURITY_DESCRIPTOR_CONTROL_SS uint16 = 0x0100 // Server Security
	NT_SECURITY_DESCRIPTOR_CONTROL_DT uint16 = 0x0200 // DACL Trusted
	NT_SECURITY_DESCRIPTOR_CONTROL_SD uint16 = 0x0400 // SACL Defaulted
	NT_SECURITY_DESCRIPTOR_CONTROL_SP uint16 = 0x0800 // SACL Present
	NT_SECURITY_DESCRIPTOR_CONTROL_DD uint16 = 0x1000 // DACL Defaulted
	NT_SECURITY_DESCRIPTOR_CONTROL_DP uint16 = 0x2000 // DACL Present
	NT_SECURITY_DESCRIPTOR_CONTROL_GD uint16 = 0x4000 // Group Defaulted
	NT_SECURITY_DESCRIPTOR_CONTROL_OD uint16 = 0x8000 // Owner Defaulted
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
	marshalledData := make([]byte, 2)
	binary.LittleEndian.PutUint16(marshalledData, nsdc.RawValue)
	return marshalledData, nil
}
