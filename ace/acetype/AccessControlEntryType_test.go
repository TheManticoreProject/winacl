package acetype_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace/acetype"
)

// TestAccessControlEntryType_Involution tests the involution property of the AccessControlEntryType's Marshal and Unmarshal methods.
func TestAccessControlEntryType_Involution(t *testing.T) {
	originalType := acetype.AccessControlEntryType{
		Value: 0x05,
	}

	// Serialize the original type to bytes
	bytesStream, err := originalType.Marshal()
	if err != nil {
		t.Errorf("Failed to marshal originalType: %v", err)
	}
	serializedBytes := bytesStream

	// Parse the serialized bytes back into a new type
	var parsedType acetype.AccessControlEntryType
	parsedType.Unmarshal(serializedBytes)

	// Check if the parsed type matches the original type
	if originalType.Value != parsedType.Value {
		t.Errorf("Involution test failed: expected 0x%02x, got 0x%02x", originalType.Value, parsedType.Value)
	}
}

// TestAccessControlEntryType_Unmarshal_EmptyReturnsError is a regression test
// for issue #30: parsers must return an error on truncated input instead of
// panicking with "index out of range".
func TestAccessControlEntryType_Unmarshal_EmptyReturnsError(t *testing.T) {
	a := acetype.AccessControlEntryType{}
	_, err := a.Unmarshal([]byte{})
	if err == nil {
		t.Fatal("expected an error for empty input, got nil")
	}
}
