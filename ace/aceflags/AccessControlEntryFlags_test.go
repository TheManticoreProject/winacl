package aceflags_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace/aceflags"
)

// TestAccessControlEntryFlag_Unmarshal_EmptyReturnsError is a regression test
// for issue #30: parsers must return an error on truncated input instead of
// panicking with "index out of range".
func TestAccessControlEntryFlag_Unmarshal_EmptyReturnsError(t *testing.T) {
	f := aceflags.AccessControlEntryFlag{}
	_, err := f.Unmarshal([]byte{})
	if err == nil {
		t.Fatal("expected an error for empty input, got nil")
	}
}
