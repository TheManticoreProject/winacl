package utils_test

import (
	"reflect"
	"testing"

	"github.com/TheManticoreProject/winacl/sddl/utils"
)

func TestMultiSplit(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		delims   []string
		expected []string
	}{
		{
			name:     "Single delimiter",
			input:    "a,b,c",
			delims:   []string{","},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "Multiple delimiters",
			input:    "a,b;c:d",
			delims:   []string{",", ";", ":"},
			expected: []string{"a", "b", "c", "d"},
		},
		{
			name:     "Empty delimiters",
			input:    "abc",
			delims:   []string{},
			expected: []string{"abc"},
		},
		{
			name:     "Empty input string",
			input:    "",
			delims:   []string{",", ";"},
			expected: []string{},
		},
		{
			name:     "Input with consecutive delimiters",
			input:    "a,,b;;c",
			delims:   []string{",", ";"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "Complex delimiters",
			input:    "key=value|name:john;age-25",
			delims:   []string{"=", "|", ":", ";", "-"},
			expected: []string{"key", "value", "name", "john", "age", "25"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utils.MultiSplit(tt.input, tt.delims)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("MultiSplit() = %v, want %v", result, tt.expected)
			}
		})
	}
}
