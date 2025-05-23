package securitydescriptor_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

func TestNtSecurityDescriptorControl_Involution(t *testing.T) {
	serializedData := make([]byte, 2)
	binary.LittleEndian.PutUint16(serializedData, uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SR|securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SP))

	control := &securitydescriptor.NtSecurityDescriptorControl{}
	_, err := control.Unmarshal(serializedData)
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Unmarshal() failed: %v", err)
	}
	data, err := control.Marshal()
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Marshal() failed: %v", err)
	}

	if !bytes.Equal(data, serializedData) {
		t.Errorf("NtSecurityDescriptorControl.Marshal() failed: Output of header.Marshal() is not equal to input rawBytes")
	}
}

func TestNtSecurityDescriptorControl_Unmarshal(t *testing.T) {
	uintValue := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SR | securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	serializedData := make([]byte, 2)
	binary.LittleEndian.PutUint16(serializedData, uintValue)
	expectedFlags := []uint16{securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SP, securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SR}

	control := &securitydescriptor.NtSecurityDescriptorControl{}
	_, err := control.Unmarshal(serializedData)
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Unmarshal() failed: %v", err)
	}

	if control.RawValue != uintValue {
		t.Errorf("Expected RawValue to be 0x%04x, but got 0x%04x", uintValue, control.RawValue)
	}

	if len(control.Flags) != len(expectedFlags) {
		t.Errorf("Expected %d flags, but got %d", len(expectedFlags), len(control.Flags))
	}

	for _, flag := range expectedFlags {
		if !control.HasControl(flag) {
			t.Errorf("Expected flag %s (%d), but it was not found", securitydescriptor.NtSecurityDescriptorControlValueToShortName[flag], flag)
		}
	}
}

func TestNtSecurityDescriptorControl_Marshal(t *testing.T) {
	uintValue := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SR | securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	serializedData := make([]byte, 2)
	binary.LittleEndian.PutUint16(serializedData, uintValue)

	control := &securitydescriptor.NtSecurityDescriptorControl{}
	_, err := control.Unmarshal(serializedData)
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Unmarshal() failed: %v", err)
	}
	data, err := control.Marshal()
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Marshal() failed: %v", err)
	}

	if !bytes.Equal(data, serializedData) {
		t.Errorf("NtSecurityDescriptorControl.Marshal() failed: Output of header.Marshal() is not equal to input rawBytes")
	}

	deserializedValue := binary.LittleEndian.Uint16(serializedData)
	if deserializedValue != uintValue {
		t.Errorf("Expected deserialized value to be 0x%04x, but got 0x%04x", uintValue, deserializedValue)
	}
}

func TestNtSecurityDescriptorControl_HasControl(t *testing.T) {
	uintValue := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SR | securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	rawValue := make([]byte, 2)
	binary.LittleEndian.PutUint16(rawValue, uintValue)
	controlFlag := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SR)

	control := &securitydescriptor.NtSecurityDescriptorControl{}
	_, err := control.Unmarshal(rawValue)
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Unmarshal() failed: %v", err)
	}

	if !control.HasControl(controlFlag) {
		t.Errorf("Expected control flag 0x%04x to be set, but it was not", controlFlag)
	}

	nonExistentFlag := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_RM)
	if control.HasControl(nonExistentFlag) {
		t.Errorf("Expected control flag 0x%04x to not be set, but it was", nonExistentFlag)
	}
}

func TestNtSecurityDescriptorControl_AddControl(t *testing.T) {
	// Initialize with some flags
	uintValue := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SR | securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	rawValue := make([]byte, 2)
	binary.LittleEndian.PutUint16(rawValue, uintValue)

	control := &securitydescriptor.NtSecurityDescriptorControl{}
	_, err := control.Unmarshal(rawValue)
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Unmarshal() failed: %v", err)
	}

	// Test adding a new control flag
	newFlag := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_RM)
	result := control.AddControl(newFlag)
	if !result {
		t.Errorf("Expected AddControl to return true when adding a new flag, but got false")
	}

	// Verify the flag was added
	if !control.HasControl(newFlag) {
		t.Errorf("Expected control flag 0x%04x to be set after AddControl, but it was not", newFlag)
	}

	// Test adding an existing control flag
	existingFlag := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SR)
	result = control.AddControl(existingFlag)
	if result {
		t.Errorf("Expected AddControl to return false when adding an existing flag, but got true")
	}

	// Verify the Values and Flags slices were updated correctly
	expectedValue := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SR | securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SP | securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_RM)
	if control.RawValue != expectedValue {
		t.Errorf("Expected RawValue to be 0x%04x after AddControl, but got 0x%04x", expectedValue, control.RawValue)
	}

	// Check if the Values slice contains the new flag
	foundFlag := false
	for _, v := range control.Values {
		if v == newFlag {
			foundFlag = true
			break
		}
	}
	if !foundFlag {
		t.Errorf("Expected Values slice to contain flag 0x%04x after AddControl, but it did not", newFlag)
	}

	// Check if the Flags slice contains the new flag's name
	flagName := securitydescriptor.NtSecurityDescriptorControlValueToShortName[newFlag]
	foundFlagName := false
	for _, f := range control.Flags {
		if f == flagName {
			foundFlagName = true
			break
		}
	}
	if !foundFlagName {
		t.Errorf("Expected Flags slice to contain flag name %s after AddControl, but it did not", flagName)
	}
}

func TestNtSecurityDescriptorControl_RemoveControl(t *testing.T) {
	// Initialize with some flags
	uintValue := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SR | securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SP | securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_RM)
	rawValue := make([]byte, 2)
	binary.LittleEndian.PutUint16(rawValue, uintValue)

	control := &securitydescriptor.NtSecurityDescriptorControl{}
	_, err := control.Unmarshal(rawValue)
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Unmarshal() failed: %v", err)
	}

	// Test removing an existing control flag
	existingFlag := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_RM)
	result := control.RemoveControl(existingFlag)
	if !result {
		t.Errorf("Expected RemoveControl to return true when removing an existing flag, but got false")
	}

	// Verify the flag was removed
	if control.HasControl(existingFlag) {
		t.Errorf("Expected control flag 0x%04x to be removed after RemoveControl, but it was still set", existingFlag)
	}

	// Test removing a non-existent control flag
	nonExistentFlag := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_DI)
	result = control.RemoveControl(nonExistentFlag)
	if result {
		t.Errorf("Expected RemoveControl to return false when removing a non-existent flag, but got true")
	}

	// Verify the Values and Flags slices were updated correctly
	expectedValue := uint16(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SR | securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	if control.RawValue != expectedValue {
		t.Errorf("Expected RawValue to be 0x%04x after RemoveControl, but got 0x%04x", expectedValue, control.RawValue)
	}

	// Check if the Values slice no longer contains the removed flag
	for _, v := range control.Values {
		if v == existingFlag {
			t.Errorf("Expected Values slice to not contain flag 0x%04x after RemoveControl, but it did", existingFlag)
		}
	}

	// Check if the Flags slice no longer contains the removed flag's name
	flagName := securitydescriptor.NtSecurityDescriptorControlValueToShortName[existingFlag]
	for _, f := range control.Flags {
		if f == flagName {
			t.Errorf("Expected Flags slice to not contain flag name %s after RemoveControl, but it did", flagName)
		}
	}
}
