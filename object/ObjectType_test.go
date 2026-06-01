package object

import (
	"encoding/hex"
	"testing"
)

// guidHex is the 16-byte binary representation of an arbitrary GUID used to
// exercise the (Inherited)ObjectType marshalling helpers.
const guidHex = "be3b0ef3f09fd111b6030000f80367c1"

// Test_ObjectType_Marshal_RawBytesSize_Idempotent verifies that repeated
// Marshal calls report the serialized size (16 bytes for a GUID) rather than
// accumulating it.
func Test_ObjectType_Marshal_RawBytesSize_Idempotent(t *testing.T) {
	raw, err := hex.DecodeString(guidHex)
	if err != nil {
		t.Fatalf("invalid test hex: %v", err)
	}

	var ot ObjectType
	if _, err := ot.Unmarshal(raw); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := ot.Marshal(); err != nil {
			t.Fatalf("Marshal() call %d error = %v", i, err)
		}
		if ot.RawBytesSize != uint32(len(raw)) {
			t.Errorf("after Marshal() call %d: RawBytesSize = %d, want %d", i, ot.RawBytesSize, len(raw))
		}
	}
}

// Test_InheritedObjectType_Marshal_RawBytesSize_Idempotent verifies the same
// invariant for InheritedObjectType.
func Test_InheritedObjectType_Marshal_RawBytesSize_Idempotent(t *testing.T) {
	raw, err := hex.DecodeString(guidHex)
	if err != nil {
		t.Fatalf("invalid test hex: %v", err)
	}

	var iot InheritedObjectType
	if _, err := iot.Unmarshal(raw); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := iot.Marshal(); err != nil {
			t.Fatalf("Marshal() call %d error = %v", i, err)
		}
		if iot.RawBytesSize != uint32(len(raw)) {
			t.Errorf("after Marshal() call %d: RawBytesSize = %d, want %d", i, iot.RawBytesSize, len(raw))
		}
	}
}
