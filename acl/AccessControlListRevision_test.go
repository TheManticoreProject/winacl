package acl

import (
	"testing"
)

func TestAccessControlListRevisionUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint8
		wantSize int
	}{
		{
			name:     "ACL_REVISION",
			input:    []byte{ACL_REVISION, 0x00, 0x00, 0x00},
			expected: ACL_REVISION,
			wantSize: 1,
		},
		{
			name:     "ACL_REVISION_DS",
			input:    []byte{ACL_REVISION_DS, 0x00, 0x00, 0x00},
			expected: ACL_REVISION_DS,
			wantSize: 1,
		},
		{
			name:     "Unknown revision",
			input:    []byte{0x01, 0x00, 0x00, 0x00},
			expected: 0x01,
			wantSize: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aclrev := AccessControlListRevision{}
			size, err := aclrev.Unmarshal(tt.input)
			if err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if size != tt.wantSize {
				t.Errorf("Unmarshal() size = %v, want %v", size, tt.wantSize)
			}
			if aclrev.Value != tt.expected {
				t.Errorf("Unmarshal() value = %v, want %v", aclrev.Value, tt.expected)
			}
		})
	}
}

func TestAccessControlListRevisionMarshal(t *testing.T) {
	tests := []struct {
		name     string
		revision uint8
		expected []byte
	}{
		{
			name:     "ACL_REVISION",
			revision: ACL_REVISION,
			expected: []byte{ACL_REVISION},
		},
		{
			name:     "ACL_REVISION_DS",
			revision: ACL_REVISION_DS,
			expected: []byte{ACL_REVISION_DS},
		},
		{
			name:     "Custom revision",
			revision: 0x01,
			expected: []byte{0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aclrev := AccessControlListRevision{Value: tt.revision}
			data, err := aclrev.Marshal()
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			if len(data) != len(tt.expected) {
				t.Fatalf("Marshal() data length = %v, want %v", len(data), len(tt.expected))
			}
			for i, b := range data {
				if b != tt.expected[i] {
					t.Errorf("Marshal() data[%d] = %v, want %v", i, b, tt.expected[i])
				}
			}
		})
	}
}

func TestAccessControlListRevisionString(t *testing.T) {
	tests := []struct {
		name     string
		revision uint8
		expected string
	}{
		{
			name:     "ACL_REVISION",
			revision: ACL_REVISION,
			expected: "ACL_REVISION",
		},
		{
			name:     "ACL_REVISION_DS",
			revision: ACL_REVISION_DS,
			expected: "ACL_REVISION_DS",
		},
		{
			name:     "Unknown revision",
			revision: 0x01,
			expected: "?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aclrev := AccessControlListRevision{Value: tt.revision}
			if got := aclrev.String(); got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}
