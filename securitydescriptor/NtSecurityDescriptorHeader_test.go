package securitydescriptor_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

func TestNtSecurityDescriptorHeader_Involution(t *testing.T) {
	hexData := "0100149ccc000000e800000014000000a0000000"
	header := &securitydescriptor.NtSecurityDescriptorHeader{}
	rawBytes, err := hex.DecodeString(hexData)
	if err != nil {
		t.Errorf("Failed to decode hexData: %v", err)
	}
	_, err = header.Unmarshal(rawBytes)
	if err != nil {
		t.Errorf("Failed to unmarshal NtSecurityDescriptorHeader: %v", err)
	}
	data, err := header.Marshal()
	if err != nil {
		t.Errorf("Failed to marshal NtSecurityDescriptorHeader: %v", err)
	}
	if !bytes.Equal(data, rawBytes) {
		t.Errorf("NtSecurityDescriptorHeader.Marshal() failed: Output of header.Marshal() is not equal to input rawBytes")
	}
}
