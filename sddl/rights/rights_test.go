package rights_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/sddl/rights"
)

// TestRightToSDDL_CollisionDeterministic verifies that the reverse map resolves
// the KR/KX mask collision (both 0x00020019) to a stable canonical token.
func TestRightToSDDL_CollisionDeterministic(t *testing.T) {
	const keyReadExecute = 0x00020019

	got, ok := rights.RightToSDDL[keyReadExecute]
	if !ok {
		t.Fatalf("RightToSDDL[0x%08x] missing", keyReadExecute)
	}
	// "KR" sorts before "KX", so it is the deterministic winner.
	if got != "KR" {
		t.Errorf("RightToSDDL[0x%08x] = %q, want %q", keyReadExecute, got, "KR")
	}
}

// TestRightToSDDL_IsValidInverse verifies that every mask present in the reverse
// map resolves to a token that maps back to that same mask in SDDLToRight, i.e.
// the reverse map is a valid inverse for every entry.
func TestRightToSDDL_IsValidInverse(t *testing.T) {
	for mask, token := range rights.RightToSDDL {
		if rights.SDDLToRight[token] != mask {
			t.Errorf("RightToSDDL[0x%08x] = %q, but SDDLToRight[%q] = 0x%08x", mask, token, token, rights.SDDLToRight[token])
		}
	}

	// Every forward mask must be representable in the reverse map.
	for token, mask := range rights.SDDLToRight {
		if _, ok := rights.RightToSDDL[mask]; !ok {
			t.Errorf("mask 0x%08x (from token %q) has no entry in RightToSDDL", mask, token)
		}
	}
}
