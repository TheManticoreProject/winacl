package mask

import (
	"testing"
)

// TestAccessControlMask_Involution tests the involution property of the AccessControlMask's Marshal and Unmarshal methods.
func TestAccessControlMask_Involution(t *testing.T) {
	originalMask := AccessControlMask{
		RawValue: 0x12345678,
	}

	// Serialize the original mask to bytes
	serializedBytes, err := originalMask.Marshal()
	if err != nil {
		t.Errorf("Failed to marshal AccessControlMask: %v", err)
	}

	// Parse the serialized bytes back into a new mask
	var parsedMask AccessControlMask
	_, err = parsedMask.Unmarshal(serializedBytes)
	if err != nil {
		t.Errorf("Failed to unmarshal AccessControlMask: %v", err)
	}

	// Check if the parsed mask matches the original mask
	if originalMask.RawValue != parsedMask.RawValue {
		t.Errorf("Involution test failed: expected 0x%08x, got 0x%08x", originalMask.RawValue, parsedMask.RawValue)
	}
}

// TestAccessControlMask_Unmarshal_TruncatedReturnsError asserts that Unmarshal
// returns a parse error instead of panicking when fewer than 4 bytes are given.
// Regression test for issue #30.
func TestAccessControlMask_Unmarshal_TruncatedReturnsError(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3} {
		buf := make([]byte, n)
		var m AccessControlMask
		_, err := m.Unmarshal(buf)
		if err == nil {
			t.Errorf("Unmarshal(%d bytes) expected error, got nil", n)
		}
	}
}
