package mask_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace/mask"
	"github.com/TheManticoreProject/winacl/rights"
)

func TestAccessControlMask_HasRight(t *testing.T) {
	acm := &mask.AccessControlMask{}
	acm.AddRight(rights.RIGHT_DS_READ_PROPERTY)

	if !acm.HasRight(rights.RIGHT_DS_READ_PROPERTY) {
		t.Error("Expected RIGHT_DS_READ_PROPERTY to be present")
	}
	if acm.HasRight(rights.RIGHT_DS_WRITE_PROPERTY) {
		t.Error("Expected RIGHT_DS_WRITE_PROPERTY to not be present")
	}
}

func TestAccessControlMask_AddRight(t *testing.T) {
	acm := &mask.AccessControlMask{}

	// Add a right
	acm.AddRight(rights.RIGHT_DS_READ_PROPERTY)

	// Check Values slice
	hasRight := false
	for _, v := range acm.Values {
		if v == rights.RIGHT_DS_READ_PROPERTY {
			hasRight = true
			break
		}
	}
	if !hasRight {
		t.Error("Expected RIGHT_DS_READ_PROPERTY to be present in Values")
	}

	// Check Flags slice
	hasFlag := false
	for _, f := range acm.Flags {
		if f == "DS_READ_PROPERTY" {
			hasFlag = true
			break
		}
	}
	if !hasFlag {
		t.Error("Expected RIGHT_DS_READ_PROPERTY to be present in Flags. Flags: ", acm.Flags)
	}

	if acm.RawValue != uint32(rights.RIGHT_DS_READ_PROPERTY) {
		t.Errorf("Expected RawValue to be %d, got %d", rights.RIGHT_DS_READ_PROPERTY, acm.RawValue)
	}

	// Add same right again - should not duplicate
	acm.AddRight(rights.RIGHT_DS_READ_PROPERTY)
	count := 0
	for _, v := range acm.Values {
		if v == rights.RIGHT_DS_READ_PROPERTY {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Expected RIGHT_DS_READ_PROPERTY to appear once, got %d occurrences", count)
	}
}

func TestAccessControlMask_RemoveRight(t *testing.T) {
	acm := &mask.AccessControlMask{}
	acm.AddRight(rights.RIGHT_DS_READ_PROPERTY)
	acm.AddRight(rights.RIGHT_DS_WRITE_PROPERTY)

	acm.RemoveRight(rights.RIGHT_DS_READ_PROPERTY)

	if acm.HasRight(rights.RIGHT_DS_READ_PROPERTY) {
		t.Error("Expected RIGHT_DS_READ_PROPERTY to be removed")
	}
	if !acm.HasRight(rights.RIGHT_DS_WRITE_PROPERTY) {
		t.Error("Expected RIGHT_DS_WRITE_PROPERTY to still be present")
	}
}

func TestAccessControlMask_SetRights(t *testing.T) {
	acm := &mask.AccessControlMask{}

	// Add initial rights
	acm.AddRight(rights.RIGHT_DS_READ_PROPERTY)

	// Set new rights
	newRights := []uint32{rights.RIGHT_DS_WRITE_PROPERTY, rights.RIGHT_DS_LIST_CONTENTS}
	acm.SetRights(newRights)

	// Check original right is gone
	if acm.HasRight(rights.RIGHT_DS_READ_PROPERTY) {
		t.Error("Expected RIGHT_DS_READ_PROPERTY to be removed")
	}

	// Check new rights are present
	if !acm.HasRight(rights.RIGHT_DS_WRITE_PROPERTY) {
		t.Error("Expected RIGHT_DS_WRITE_PROPERTY to be present")
	}
	if !acm.HasRight(rights.RIGHT_DS_LIST_CONTENTS) {
		t.Error("Expected RIGHT_DS_LIST_CONTENTS to be present")
	}
}

func TestAccessControlMask_Equal(t *testing.T) {
	acm1 := &mask.AccessControlMask{}
	acm2 := &mask.AccessControlMask{}

	// Both empty masks should be equal
	if !acm1.Equal(acm2) {
		t.Error("Expected empty masks to be equal")
	}

	// Add same rights to both
	acm1.AddRight(rights.RIGHT_DS_READ_PROPERTY)
	acm2.AddRight(rights.RIGHT_DS_READ_PROPERTY)
	if !acm1.Equal(acm2) {
		t.Error("Expected masks with same rights to be equal")
	}

	// Add different right to second mask
	acm2.AddRight(rights.RIGHT_DS_WRITE_PROPERTY)
	if acm1.Equal(acm2) {
		t.Error("Expected masks with different rights to not be equal")
	}

	// Nil comparison
	if acm1.Equal(nil) {
		t.Error("Expected non-nil mask to not equal nil")
	}
	if !(*mask.AccessControlMask)(nil).Equal(nil) {
		t.Error("Expected nil mask to equal nil")
	}
}
