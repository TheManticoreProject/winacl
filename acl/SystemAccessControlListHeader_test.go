package acl

import (
	"bytes"
	"testing"
)

func TestSystemAccessControlListHeader_MarshalUnmarshal(t *testing.T) {
	// Create a test header with known values
	original := SystemAccessControlListHeader{
		Revision: AccessControlListRevision{
			Value: 0x02,
		},
		Sbz1:     0x00,
		AclSize:  0x30,
		AceCount: 0x05,
		Sbz2:     0x00,
	}

	// Marshal the header to bytes
	marshalledData, err := original.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal SystemAccessControlListHeader: %v", err)
	}

	// Create a new header to unmarshal into
	unmarshalled := SystemAccessControlListHeader{}

	// Unmarshal the bytes back into the new header
	_, err = unmarshalled.Unmarshal(marshalledData)
	if err != nil {
		t.Fatalf("Failed to unmarshal SystemAccessControlListHeader: %v", err)
	}

	// Verify that all fields match
	if original.Revision.Value != unmarshalled.Revision.Value {
		t.Errorf("Revision mismatch: expected %d, got %d", original.Revision.Value, unmarshalled.Revision.Value)
	}
	if original.Sbz1 != unmarshalled.Sbz1 {
		t.Errorf("Sbz1 mismatch: expected %d, got %d", original.Sbz1, unmarshalled.Sbz1)
	}
	if original.AclSize != unmarshalled.AclSize {
		t.Errorf("AclSize mismatch: expected %d, got %d", original.AclSize, unmarshalled.AclSize)
	}
	if original.AceCount != unmarshalled.AceCount {
		t.Errorf("AceCount mismatch: expected %d, got %d", original.AceCount, unmarshalled.AceCount)
	}
	if original.Sbz2 != unmarshalled.Sbz2 {
		t.Errorf("Sbz2 mismatch: expected %d, got %d", original.Sbz2, unmarshalled.Sbz2)
	}

	// Marshal the unmarshalled header again
	remarshalled, err := unmarshalled.Marshal()
	if err != nil {
		t.Fatalf("Failed to remarshal SystemAccessControlListHeader: %v", err)
	}

	// Verify that the original marshalled data matches the remarshalled data
	if !bytes.Equal(marshalledData, remarshalled) {
		t.Errorf("Marshaled data mismatch: original and remarshalled data are not equal")
	}
}

func TestSystemAccessControlListHeader_MarshalUnmarshalWithEdgeCases(t *testing.T) {
	testCases := []struct {
		name     string
		header   SystemAccessControlListHeader
		expected SystemAccessControlListHeader
	}{
		{
			name: "Zero values",
			header: SystemAccessControlListHeader{
				Revision: AccessControlListRevision{Value: 0},
				Sbz1:     0,
				AclSize:  0,
				AceCount: 0,
				Sbz2:     0,
			},
			expected: SystemAccessControlListHeader{
				Revision: AccessControlListRevision{Value: 0},
				Sbz1:     0,
				AclSize:  0,
				AceCount: 0,
				Sbz2:     0,
			},
		},
		{
			name: "Maximum values",
			header: SystemAccessControlListHeader{
				Revision: AccessControlListRevision{Value: 0xFF},
				Sbz1:     0xFF,
				AclSize:  0xFFFF,
				AceCount: 0xFFFF,
				Sbz2:     0xFFFF,
			},
			expected: SystemAccessControlListHeader{
				Revision: AccessControlListRevision{Value: 0xFF},
				Sbz1:     0xFF,
				AclSize:  0xFFFF,
				AceCount: 0xFFFF,
				Sbz2:     0xFFFF,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Marshal the header
			marshalledData, err := tc.header.Marshal()
			if err != nil {
				t.Fatalf("Failed to marshal header: %v", err)
			}

			// Unmarshal into a new header
			unmarshalled := SystemAccessControlListHeader{}
			_, err = unmarshalled.Unmarshal(marshalledData)
			if err != nil {
				t.Fatalf("Failed to unmarshal header: %v", err)
			}

			// Verify fields match expected values
			if tc.expected.Revision.Value != unmarshalled.Revision.Value {
				t.Errorf("Revision mismatch: expected %d, got %d", tc.expected.Revision.Value, unmarshalled.Revision.Value)
			}
			if tc.expected.Sbz1 != unmarshalled.Sbz1 {
				t.Errorf("Sbz1 mismatch: expected %d, got %d", tc.expected.Sbz1, unmarshalled.Sbz1)
			}
			if tc.expected.AclSize != unmarshalled.AclSize {
				t.Errorf("AclSize mismatch: expected %d, got %d", tc.expected.AclSize, unmarshalled.AclSize)
			}
			if tc.expected.AceCount != unmarshalled.AceCount {
				t.Errorf("AceCount mismatch: expected %d, got %d", tc.expected.AceCount, unmarshalled.AceCount)
			}
			if tc.expected.Sbz2 != unmarshalled.Sbz2 {
				t.Errorf("Sbz2 mismatch: expected %d, got %d", tc.expected.Sbz2, unmarshalled.Sbz2)
			}
		})
	}
}
