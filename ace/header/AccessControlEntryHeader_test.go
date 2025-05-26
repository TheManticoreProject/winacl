package header_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/TheManticoreProject/winacl/ace/header"
)

func TestAccessControlEntryHeader_Involution(t *testing.T) {
	hexData := "1122abcd"
	header := &header.AccessControlEntryHeader{}
	rawBytes, err := hex.DecodeString(hexData)
	if err != nil {
		t.Errorf("Failed to decode hexData: %v", err)
	}
	_, err = header.Unmarshal(rawBytes)
	if err != nil {
		t.Errorf("Failed to unmarshal AccessControlEntryHeader: %v", err)
	}
	serializedBytes, err := header.Marshal()
	if err != nil {
		t.Errorf("Failed to marshal AccessControlEntryHeader: %v", err)
	}
	if !bytes.Equal(serializedBytes, rawBytes) {
		t.Errorf("AccessControlEntryHeader.Marshal() failed: Output of header.Marshal() is not equal to input rawBytes")
	}
}
