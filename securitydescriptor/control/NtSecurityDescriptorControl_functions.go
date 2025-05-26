package control

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

// ClearControls removes all control bits from the RawValue and clears the Values and Flags slices.
func (nsdc *NtSecurityDescriptorControl) ClearControls() {
	nsdc.RawValue = 0
	nsdc.Values = []uint16{}
	nsdc.Flags = []string{}
}

// Equal compares two NtSecurityDescriptorControl instances for equality.
//
// Parameters:
//   - other (*NtSecurityDescriptorControl): The NtSecurityDescriptorControl to compare with.
//
// Returns:
//   - bool: True if the NtSecurityDescriptorControls are equal, false otherwise.
func (nsdc *NtSecurityDescriptorControl) Equal(other *NtSecurityDescriptorControl) bool {
	if nsdc == nil || other == nil {
		return nsdc == other
	}

	if nsdc.RawValue != other.RawValue {
		return false
	}

	if len(nsdc.Values) != len(other.Values) {
		return false
	}

	if len(nsdc.Flags) != len(other.Flags) {
		return false
	}

	// Compare Values slices
	for i, value := range nsdc.Values {
		if value != other.Values[i] {
			return false
		}
	}

	// Compare Flags slices
	for i, flag := range nsdc.Flags {
		if flag != other.Flags[i] {
			return false
		}
	}

	return true
}
