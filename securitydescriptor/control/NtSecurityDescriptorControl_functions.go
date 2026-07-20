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

	// RawValue is the single 16-bit SECURITY_DESCRIPTOR_CONTROL word (MS-DTYP
	// 2.4.6) and fully, canonically encodes the set of control bits. The Values
	// and Flags slices are merely a derived, per-bit view built by Unmarshal via
	// Go map iteration, whose order is randomized; comparing them positionally
	// made two controls decoded from identical bytes compare unequal about half
	// the time. Equality is therefore defined by RawValue alone.
	return nsdc.RawValue == other.RawValue
}
