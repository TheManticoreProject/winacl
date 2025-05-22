package acl

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDiscretionaryAccessControlListHeader_Involution(t *testing.T) {
	// Test case with sample DACL header data
	testDaclHeaderHex := "0100140002000000" // Revision: 1, Sbz1: 0, AclSize: 20, AceCount: 2, Sbz2: 0

	daclHeader := &DiscretionaryAccessControlListHeader{}
	daclHeaderBytes, err := hex.DecodeString(testDaclHeaderHex)
	if err != nil {
		t.Errorf("Failed to decode testDaclHeaderHex: %v", err)
	}

	// Unmarshal the test data
	_, err = daclHeader.Unmarshal(daclHeaderBytes)
	if err != nil {
		t.Errorf("Failed to unmarshal DiscretionaryAccessControlListHeader: %v", err)
	}

	// Verify the unmarshalled values
	if daclHeader.Revision.Value != 1 {
		t.Errorf("Expected Revision to be 1, got %d", daclHeader.Revision.Value)
	}
	if daclHeader.Sbz1 != 0 {
		t.Errorf("Expected Sbz1 to be 0, got %d", daclHeader.Sbz1)
	}
	if daclHeader.AclSize != 20 {
		t.Errorf("Expected AclSize to be 20, got %d", daclHeader.AclSize)
	}
	if daclHeader.AceCount != 2 {
		t.Errorf("Expected AceCount to be 2, got %d", daclHeader.AceCount)
	}
	if daclHeader.Sbz2 != 0 {
		t.Errorf("Expected Sbz2 to be 0, got %d", daclHeader.Sbz2)
	}

	// Marshal the data back
	serializedBytes, err := daclHeader.Marshal()
	if err != nil {
		t.Errorf("Failed to marshal DiscretionaryAccessControlListHeader: %v", err)
	}

	// Verify the marshalled data matches the original
	if !bytes.Equal(daclHeaderBytes, serializedBytes) {
		t.Errorf("Marshal/Unmarshal involution failed: original and serialized bytes don't match\nOriginal: %x\nSerialized: %x",
			daclHeaderBytes, serializedBytes)
	}

	// Test the involution by unmarshalling the marshalled data
	daclHeader2 := &DiscretionaryAccessControlListHeader{}
	_, err = daclHeader2.Unmarshal(serializedBytes)
	if err != nil {
		t.Errorf("Failed to unmarshal serialized DiscretionaryAccessControlListHeader: %v", err)
	}

	// Verify all values are preserved
	if daclHeader.Revision != daclHeader2.Revision {
		t.Errorf("Revision value not preserved: expected %d, got %d", daclHeader.Revision, daclHeader2.Revision)
	}
	if daclHeader.Sbz1 != daclHeader2.Sbz1 {
		t.Errorf("Sbz1 value not preserved: expected %d, got %d", daclHeader.Sbz1, daclHeader2.Sbz1)
	}
	if daclHeader.AclSize != daclHeader2.AclSize {
		t.Errorf("AclSize value not preserved: expected %d, got %d", daclHeader.AclSize, daclHeader2.AclSize)
	}
	if daclHeader.AceCount != daclHeader2.AceCount {
		t.Errorf("AceCount value not preserved: expected %d, got %d", daclHeader.AceCount, daclHeader2.AceCount)
	}
	if daclHeader.Sbz2 != daclHeader2.Sbz2 {
		t.Errorf("Sbz2 value not preserved: expected %d, got %d", daclHeader.Sbz2, daclHeader2.Sbz2)
	}
}
