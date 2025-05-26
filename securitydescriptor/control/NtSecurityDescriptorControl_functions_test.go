package control_test

import (
	"encoding/binary"
	"testing"

	"github.com/TheManticoreProject/winacl/securitydescriptor/control"
)

func TestNtSecurityDescriptorControl_HasControl(t *testing.T) {
	uintValue := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_SR | control.NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	rawValue := make([]byte, 2)
	binary.LittleEndian.PutUint16(rawValue, uintValue)
	controlFlag := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_SR)

	c := &control.NtSecurityDescriptorControl{}
	_, err := c.Unmarshal(rawValue)
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Unmarshal() failed: %v", err)
	}

	if !c.HasControl(controlFlag) {
		t.Errorf("Expected control flag 0x%04x to be set, but it was not", controlFlag)
	}

	nonExistentFlag := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_RM)
	if c.HasControl(nonExistentFlag) {
		t.Errorf("Expected control flag 0x%04x to not be set, but it was", nonExistentFlag)
	}
}

func TestNtSecurityDescriptorControl_AddControl(t *testing.T) {
	// Initialize with some flags
	uintValue := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_SR | control.NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	rawValue := make([]byte, 2)
	binary.LittleEndian.PutUint16(rawValue, uintValue)

	c := &control.NtSecurityDescriptorControl{}
	_, err := c.Unmarshal(rawValue)
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Unmarshal() failed: %v", err)
	}

	// Test adding a new control flag
	newFlag := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_RM)
	result := c.AddControl(newFlag)
	if !result {
		t.Errorf("Expected AddControl to return true when adding a new flag, but got false")
	}

	// Verify the flag was added
	if !c.HasControl(newFlag) {
		t.Errorf("Expected control flag 0x%04x to be set after AddControl, but it was not", newFlag)
	}

	// Test adding an existing control flag
	existingFlag := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_SR)
	result = c.AddControl(existingFlag)
	if result {
		t.Errorf("Expected AddControl to return false when adding an existing flag, but got true")
	}

	// Verify the Values and Flags slices were updated correctly
	expectedValue := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_SR | control.NT_SECURITY_DESCRIPTOR_CONTROL_SP | control.NT_SECURITY_DESCRIPTOR_CONTROL_RM)
	if c.RawValue != expectedValue {
		t.Errorf("Expected RawValue to be 0x%04x after AddControl, but got 0x%04x", expectedValue, c.RawValue)
	}

	// Check if the Values slice contains the new flag
	foundFlag := false
	for _, v := range c.Values {
		if v == newFlag {
			foundFlag = true
			break
		}
	}
	if !foundFlag {
		t.Errorf("Expected Values slice to contain flag 0x%04x after AddControl, but it did not", newFlag)
	}

	// Check if the Flags slice contains the new flag's name
	flagName := control.NtSecurityDescriptorControlValueToShortName[newFlag]
	foundFlagName := false
	for _, f := range c.Flags {
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
	uintValue := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_SR | control.NT_SECURITY_DESCRIPTOR_CONTROL_SP | control.NT_SECURITY_DESCRIPTOR_CONTROL_RM)
	rawValue := make([]byte, 2)
	binary.LittleEndian.PutUint16(rawValue, uintValue)

	c := &control.NtSecurityDescriptorControl{}
	_, err := c.Unmarshal(rawValue)
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Unmarshal() failed: %v", err)
	}

	// Test removing an existing control flag
	existingFlag := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_RM)
	result := c.RemoveControl(existingFlag)
	if !result {
		t.Errorf("Expected RemoveControl to return true when removing an existing flag, but got false")
	}

	// Verify the flag was removed
	if c.HasControl(existingFlag) {
		t.Errorf("Expected control flag 0x%04x to be removed after RemoveControl, but it was still set", existingFlag)
	}

	// Test removing a non-existent control flag
	nonExistentFlag := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_DI)
	result = c.RemoveControl(nonExistentFlag)
	if result {
		t.Errorf("Expected RemoveControl to return false when removing a non-existent flag, but got true")
	}

	// Verify the Values and Flags slices were updated correctly
	expectedValue := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_SR | control.NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	if c.RawValue != expectedValue {
		t.Errorf("Expected RawValue to be 0x%04x after RemoveControl, but got 0x%04x", expectedValue, c.RawValue)
	}

	// Check if the Values slice no longer contains the removed flag
	for _, v := range c.Values {
		if v == existingFlag {
			t.Errorf("Expected Values slice to not contain flag 0x%04x after RemoveControl, but it did", existingFlag)
		}
	}

	// Check if the Flags slice no longer contains the removed flag's name
	flagName := control.NtSecurityDescriptorControlValueToShortName[existingFlag]
	for _, f := range c.Flags {
		if f == flagName {
			t.Errorf("Expected Flags slice to not contain flag name %s after RemoveControl, but it did", flagName)
		}
	}
}

func TestNtSecurityDescriptorControl_Equal(t *testing.T) {
	// Create two empty controls
	control1 := &control.NtSecurityDescriptorControl{}
	control2 := &control.NtSecurityDescriptorControl{}

	// Test when both controls are empty/default
	if !control1.Equal(control2) {
		t.Error("Equal() returned false for identical empty controls")
	}

	// Test when controls have same values
	flags := []uint16{
		control.NT_SECURITY_DESCRIPTOR_CONTROL_SR,
		control.NT_SECURITY_DESCRIPTOR_CONTROL_SP,
	}
	for _, flag := range flags {
		control1.AddControl(flag)
		control2.AddControl(flag)
	}

	if !control1.Equal(control2) {
		t.Error("Equal() returned false for identical populated controls")
	}

	// Test when controls have different values
	control2.AddControl(control.NT_SECURITY_DESCRIPTOR_CONTROL_RM)
	if control1.Equal(control2) {
		t.Error("Equal() returned true for controls with different values")
	}

	// Test with nil
	if control1.Equal(nil) {
		t.Error("Equal() returned true when comparing with nil")
	}

	// Test nil with nil
	var nilControl1, nilControl2 *control.NtSecurityDescriptorControl
	if !nilControl1.Equal(nilControl2) {
		t.Error("Equal() returned false when comparing nil with nil")
	}
}
