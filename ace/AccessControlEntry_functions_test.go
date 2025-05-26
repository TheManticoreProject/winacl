package ace_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/aceflags"
	"github.com/TheManticoreProject/winacl/ace/acetype"
)

func TestAccessControlEntry_Equal(t *testing.T) {
	// Test nil comparison
	var ace1 *ace.AccessControlEntry
	var ace2 *ace.AccessControlEntry
	if !ace1.Equal(ace2) {
		t.Error("Expected nil ACEs to be equal")
	}

	// Test one nil, one non-nil
	ace2 = &ace.AccessControlEntry{}
	if ace1.Equal(ace2) {
		t.Error("Expected nil and non-nil ACEs to be unequal")
	}

	// Test equal ACEs
	ace1 = &ace.AccessControlEntry{}
	ace2 = &ace.AccessControlEntry{}

	// Set identical values
	ace1.Header.Type.SetType(acetype.ACE_TYPE_ACCESS_ALLOWED)
	ace2.Header.Type.SetType(acetype.ACE_TYPE_ACCESS_ALLOWED)

	ace1.Header.Flags.Values = []uint8{aceflags.ACE_FLAG_INHERITED}
	ace2.Header.Flags.Values = []uint8{aceflags.ACE_FLAG_INHERITED}

	ace1.Identity.SID.FromString("S-1-5-32-544")
	ace2.Identity.SID.FromString("S-1-5-32-544")

	if !ace1.Equal(ace2) {
		t.Error("Expected identical ACEs to be equal")
	}

	// Test unequal ACEs
	ace2.Header.Type.SetType(acetype.ACE_TYPE_ACCESS_DENIED)
	if ace1.Equal(ace2) {
		t.Error("Expected ACEs with different types to be unequal")
	}

	// Reset type and change flags
	ace2.Header.Type.SetType(acetype.ACE_TYPE_ACCESS_ALLOWED)
	ace2.Header.Flags.Values = []uint8{aceflags.ACE_FLAG_CONTAINER_INHERIT}
	if ace1.Equal(ace2) {
		t.Error("Expected ACEs with different flags to be unequal")
	}

	// Reset flags and change SID
	ace2.Header.Flags.Values = []uint8{aceflags.ACE_FLAG_INHERITED}
	ace2.Identity.SID.FromString("S-1-5-32-545")
	if ace1.Equal(ace2) {
		t.Error("Expected ACEs with different SIDs to be unequal")
	}
}
