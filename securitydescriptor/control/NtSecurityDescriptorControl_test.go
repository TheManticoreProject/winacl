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

// TestNtSecurityDescriptorControl_Unmarshal_TruncatedReturnsError is a
// regression test for issue #30: parsers must return a parse error on
// truncated input instead of panicking.
func TestNtSecurityDescriptorControl_Unmarshal_TruncatedReturnsError(t *testing.T) {
	for _, n := range []int{0, 1} {
		buf := make([]byte, n)
		c := &control.NtSecurityDescriptorControl{}
		_, err := c.Unmarshal(buf)
		if err == nil {
			t.Errorf("Unmarshal(%d bytes) expected error, got nil", n)
		}
	}
}

// TestNtSecurityDescriptorControl_WireValues asserts the control flag constants
// match the MS-DTYP / winnt.h little-endian wire layout (SE_* values). A
// regression here means descriptors marshaled by this library carry a malformed
// Control word that NT servers reject. See issue #92.
func TestNtSecurityDescriptorControl_WireValues(t *testing.T) {
	cases := []struct {
		name string
		got  uint16
		want uint16
	}{
		{"SE_OWNER_DEFAULTED", control.NT_SECURITY_DESCRIPTOR_CONTROL_OD, 0x0001},
		{"SE_GROUP_DEFAULTED", control.NT_SECURITY_DESCRIPTOR_CONTROL_GD, 0x0002},
		{"SE_DACL_PRESENT", control.NT_SECURITY_DESCRIPTOR_CONTROL_DP, 0x0004},
		{"SE_DACL_DEFAULTED", control.NT_SECURITY_DESCRIPTOR_CONTROL_DD, 0x0008},
		{"SE_SACL_PRESENT", control.NT_SECURITY_DESCRIPTOR_CONTROL_SP, 0x0010},
		{"SE_SACL_DEFAULTED", control.NT_SECURITY_DESCRIPTOR_CONTROL_SD, 0x0020},
		{"SE_DACL_AUTO_INHERIT_REQ", control.NT_SECURITY_DESCRIPTOR_CONTROL_DC, 0x0100},
		{"SE_SACL_AUTO_INHERIT_REQ", control.NT_SECURITY_DESCRIPTOR_CONTROL_SC, 0x0200},
		{"SE_DACL_AUTO_INHERITED", control.NT_SECURITY_DESCRIPTOR_CONTROL_DI, 0x0400},
		{"SE_SACL_AUTO_INHERITED", control.NT_SECURITY_DESCRIPTOR_CONTROL_SI, 0x0800},
		{"SE_DACL_PROTECTED", control.NT_SECURITY_DESCRIPTOR_CONTROL_PD, 0x1000},
		{"SE_SACL_PROTECTED", control.NT_SECURITY_DESCRIPTOR_CONTROL_PS, 0x2000},
		{"SE_RM_CONTROL_VALID", control.NT_SECURITY_DESCRIPTOR_CONTROL_RM, 0x4000},
		{"SE_SELF_RELATIVE", control.NT_SECURITY_DESCRIPTOR_CONTROL_SR, 0x8000},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: got 0x%04x, want 0x%04x", tc.name, tc.got, tc.want)
		}
	}
}
