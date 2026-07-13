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

// TestAccessControlEntryFlag_Unmarshal_NoneNotSetWhenFlagsPresent is a
// regression test for issue #94: the zero-valued NONE flag must not be
// reported when actual flag bits are set.
func TestAccessControlEntryFlag_Unmarshal_NoneNotSetWhenFlagsPresent(t *testing.T) {
	f := aceflags.AccessControlEntryFlag{}
	if _, err := f.Unmarshal([]byte{aceflags.ACE_FLAG_OBJECT_INHERIT}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := f.String(); got != "OBJECT_INHERIT" {
		t.Fatalf("expected flags %q, got %q", "OBJECT_INHERIT", got)
	}

	for _, name := range f.Flags {
		if name == "NONE" {
			t.Fatalf("NONE must not be present when flag bits are set, got flags %v", f.Flags)
		}
	}
	for _, v := range f.Values {
		if v == aceflags.ACE_FLAG_NONE {
			t.Fatalf("ACE_FLAG_NONE must not be present when flag bits are set, got values %v", f.Values)
		}
	}
}

// TestAccessControlEntryFlag_Unmarshal_NoneWhenNoBitsSet verifies that NONE is
// reported when no flag bits are set.
func TestAccessControlEntryFlag_Unmarshal_NoneWhenNoBitsSet(t *testing.T) {
	f := aceflags.AccessControlEntryFlag{}
	if _, err := f.Unmarshal([]byte{aceflags.ACE_FLAG_NONE}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := f.String(); got != "NONE" {
		t.Fatalf("expected flags %q, got %q", "NONE", got)
	}
}
