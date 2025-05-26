package acetype_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace/acetype"
)

func TestAccessControlEntryTypeGetSet(t *testing.T) {
	tests := []struct {
		name     string
		aceType  uint8
		expected uint8
	}{
		{
			name:     "Test ACCESS_ALLOWED type",
			aceType:  acetype.ACE_TYPE_ACCESS_ALLOWED,
			expected: 0x00,
		},
		{
			name:     "Test ACCESS_DENIED type",
			aceType:  acetype.ACE_TYPE_ACCESS_DENIED,
			expected: 0x01,
		},
		{
			name:     "Test SYSTEM_AUDIT type",
			aceType:  acetype.ACE_TYPE_SYSTEM_AUDIT,
			expected: 0x02,
		},
		{
			name:     "Test SYSTEM_MANDATORY_LABEL type",
			aceType:  acetype.ACE_TYPE_SYSTEM_MANDATORY_LABEL,
			expected: 0x11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aceType := &acetype.AccessControlEntryType{}

			// Test SetType
			aceType.SetType(tt.aceType)
			if aceType.Value != tt.expected {
				t.Errorf("SetType() = %v, want %v", aceType.Value, tt.expected)
			}

			// Test GetType
			got := aceType.GetType()
			if got != tt.expected {
				t.Errorf("GetType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAccessControlEntryTypeString(t *testing.T) {
	tests := []struct {
		name     string
		aceType  uint8
		expected string
	}{
		{
			name:     "Test ACCESS_ALLOWED type",
			aceType:  acetype.ACE_TYPE_ACCESS_ALLOWED,
			expected: "ACCESS_ALLOWED",
		},
		{
			name:     "Test ACCESS_DENIED type",
			aceType:  acetype.ACE_TYPE_ACCESS_DENIED,
			expected: "ACCESS_DENIED",
		},
		{
			name:     "Test SYSTEM_AUDIT type",
			aceType:  acetype.ACE_TYPE_SYSTEM_AUDIT,
			expected: "SYSTEM_AUDIT",
		},

		{
			name:     "Test SYSTEM_MANDATORY_LABEL type",
			aceType:  acetype.ACE_TYPE_SYSTEM_MANDATORY_LABEL,
			expected: "SYSTEM_MANDATORY_LABEL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aceType := &acetype.AccessControlEntryType{}
			aceType.SetType(tt.aceType)
			if aceType.String() != tt.expected {
				t.Errorf("String() = %v, want %v", aceType.String(), tt.expected)
			}
		})
	}
}
