package control_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/TheManticoreProject/winacl/securitydescriptor/control"
)

func TestNtSecurityDescriptorControl_Involution(t *testing.T) {
	marshalledData := make([]byte, 2)
	binary.LittleEndian.PutUint16(marshalledData, uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_SR|control.NT_SECURITY_DESCRIPTOR_CONTROL_SP))

	control := &control.NtSecurityDescriptorControl{}
	_, err := control.Unmarshal(marshalledData)
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Unmarshal() failed: %v", err)
	}
	data, err := control.Marshal()
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Marshal() failed: %v", err)
	}

	if !bytes.Equal(data, marshalledData) {
		t.Errorf("NtSecurityDescriptorControl.Marshal() failed: Output of header.Marshal() is not equal to input rawBytes")
	}
}

func TestNtSecurityDescriptorControl_Unmarshal(t *testing.T) {
	uintValue := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_SR | control.NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	marshalledData := make([]byte, 2)
	binary.LittleEndian.PutUint16(marshalledData, uintValue)
	expectedFlags := []uint16{control.NT_SECURITY_DESCRIPTOR_CONTROL_SP, control.NT_SECURITY_DESCRIPTOR_CONTROL_SR}

	c := &control.NtSecurityDescriptorControl{}
	_, err := c.Unmarshal(marshalledData)
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Unmarshal() failed: %v", err)
	}

	if c.RawValue != uintValue {
		t.Errorf("Expected RawValue to be 0x%04x, but got 0x%04x", uintValue, c.RawValue)
	}

	if len(c.Flags) != len(expectedFlags) {
		t.Errorf("Expected %d flags, but got %d", len(expectedFlags), len(c.Flags))
	}

	for _, flag := range expectedFlags {
		if !c.HasControl(flag) {
			t.Errorf("Expected flag %s (%d), but it was not found", control.NtSecurityDescriptorControlValueToName[flag], flag)
		}
	}
}

func TestNtSecurityDescriptorControl_Marshal(t *testing.T) {
	uintValue := uint16(control.NT_SECURITY_DESCRIPTOR_CONTROL_SR | control.NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	marshalledData := make([]byte, 2)
	binary.LittleEndian.PutUint16(marshalledData, uintValue)

	control := &control.NtSecurityDescriptorControl{}
	_, err := control.Unmarshal(marshalledData)
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Unmarshal() failed: %v", err)
	}
	data, err := control.Marshal()
	if err != nil {
		t.Errorf("NtSecurityDescriptorControl.Marshal() failed: %v", err)
	}

	if !bytes.Equal(data, marshalledData) {
		t.Errorf("NtSecurityDescriptorControl.Marshal() failed: Output of header.Marshal() is not equal to input rawBytes")
	}

	deserializedValue := binary.LittleEndian.Uint16(marshalledData)
	if deserializedValue != uintValue {
		t.Errorf("Expected deserialized value to be 0x%04x, but got 0x%04x", uintValue, deserializedValue)
	}
}
