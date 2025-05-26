package aceflags

import (
	"testing"
)

func TestAccessControlEntryFlag_Equal(t *testing.T) {
	tests := []struct {
		name     string
		flag1    *AccessControlEntryFlag
		flag2    *AccessControlEntryFlag
		expected bool
	}{
		{
			name:     "Both nil",
			flag1:    nil,
			flag2:    nil,
			expected: true,
		},
		{
			name:     "First nil",
			flag1:    nil,
			flag2:    &AccessControlEntryFlag{},
			expected: false,
		},
		{
			name:     "Second nil",
			flag1:    &AccessControlEntryFlag{},
			flag2:    nil,
			expected: false,
		},
		{
			name: "Different RawValue",
			flag1: &AccessControlEntryFlag{
				RawValue: 0x01,
				Values:   []uint8{0x01},
				Flags:    []string{"OBJECT_INHERIT"},
			},
			flag2: &AccessControlEntryFlag{
				RawValue: 0x02,
				Values:   []uint8{0x02},
				Flags:    []string{"CONTAINER_INHERIT"},
			},
			expected: false,
		},
		{
			name: "Different Values length",
			flag1: &AccessControlEntryFlag{
				RawValue: 0x03,
				Values:   []uint8{0x01, 0x02},
				Flags:    []string{"OBJECT_INHERIT", "CONTAINER_INHERIT"},
			},
			flag2: &AccessControlEntryFlag{
				RawValue: 0x03,
				Values:   []uint8{0x01},
				Flags:    []string{"OBJECT_INHERIT"},
			},
			expected: false,
		},
		{
			name: "Different Values content",
			flag1: &AccessControlEntryFlag{
				RawValue: 0x03,
				Values:   []uint8{0x01, 0x02},
				Flags:    []string{"OBJECT_INHERIT", "CONTAINER_INHERIT"},
			},
			flag2: &AccessControlEntryFlag{
				RawValue: 0x03,
				Values:   []uint8{0x01, 0x04},
				Flags:    []string{"OBJECT_INHERIT", "NO_PROPAGATE_INHERIT"},
			},
			expected: false,
		},
		{
			name: "Equal flags",
			flag1: &AccessControlEntryFlag{
				RawValue: 0x03,
				Values:   []uint8{0x01, 0x02},
				Flags:    []string{"OBJECT_INHERIT", "CONTAINER_INHERIT"},
			},
			flag2: &AccessControlEntryFlag{
				RawValue: 0x03,
				Values:   []uint8{0x01, 0x02},
				Flags:    []string{"OBJECT_INHERIT", "CONTAINER_INHERIT"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flag1.Equal(tt.flag2)
			if result != tt.expected {
				t.Errorf("Equal() = %v, want %v", result, tt.expected)
			}
		})
	}
}
