package flags_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/object/flags"
)

func TestAccessControlObjectTypeFlags_Functions(t *testing.T) {
	tests := []struct {
		name     string
		flags    flags.AccessControlObjectTypeFlags
		expected bool
	}{
		{
			name:     "No flags set",
			flags:    flags.AccessControlObjectTypeFlags{Value: flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE},
			expected: true,
		},
		{
			name:     "ObjectType flag set",
			flags:    flags.AccessControlObjectTypeFlags{Value: flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT},
			expected: false,
		},
		{
			name:     "InheritedObjectType flag set",
			flags:    flags.AccessControlObjectTypeFlags{Value: flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT},
			expected: false,
		},
		{
			name: "Both flags set",
			flags: flags.AccessControlObjectTypeFlags{Value: flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT |
				flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test IsNone()
			if got := tt.flags.IsNone(); got != tt.expected {
				t.Errorf("IsNone() = %v, want %v", got, tt.expected)
			}

			// Test IsObjectTypePresent()
			if got := tt.flags.IsObjectTypePresent(); got != ((tt.flags.Value & flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) != 0) {
				t.Errorf("IsObjectTypePresent() = %v, want %v", got, (tt.flags.Value&flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) != 0)
			}

			// Test IsInheritedObjectTypePresent()
			if got := tt.flags.IsInheritedObjectTypePresent(); got != ((tt.flags.Value & flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT) != 0) {
				t.Errorf("IsInheritedObjectTypePresent() = %v, want %v", got, (tt.flags.Value&flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT) != 0)
			}
		})
	}
}

func TestAccessControlObjectTypeFlags_Modifications(t *testing.T) {
	t.Run("Setting and clearing flags", func(t *testing.T) {
		flags := flags.AccessControlObjectTypeFlags{}

		// Test setting ObjectType flag
		flags.SetObjectTypePresent()
		if !flags.IsObjectTypePresent() {
			t.Error("SetObjectTypePresent() failed to set flag")
		}

		// Test setting InheritedObjectType flag
		flags.SetInheritedObjectTypePresent()
		if !flags.IsInheritedObjectTypePresent() {
			t.Error("SetInheritedObjectTypePresent() failed to set flag")
		}

		// Test clearing ObjectType flag
		flags.ClearObjectTypePresent()
		if flags.IsObjectTypePresent() {
			t.Error("ClearObjectTypePresent() failed to clear flag")
		}

		// Test clearing InheritedObjectType flag
		flags.ClearInheritedObjectTypePresent()
		if flags.IsInheritedObjectTypePresent() {
			t.Error("ClearInheritedObjectTypePresent() failed to clear flag")
		}

		// Test Clear() function
		flags.SetObjectTypePresent()
		flags.SetInheritedObjectTypePresent()
		flags.Clear()
		if !flags.IsNone() {
			t.Error("Clear() failed to clear all flags")
		}
	})
}
