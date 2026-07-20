package condition_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/ace/condition"
)

// TestMemberOf_BareSIDOperand_RoundTrips is a regression test for a Member_of
// whose binary operand is a bare SID literal (spec-valid per MS-DTYP 2.4.4.17.6)
// serializing to brace-less `Member_of SID(...)`, which the parser then could
// not re-parse. The serializer must wrap it in a SID array.
//
// Hand-built wire: artx + SID literal (0x51, len 12, S-1-1-0) + Member_of (0x89) + padding.
func TestMemberOf_BareSIDOperand_RoundTrips(t *testing.T) {
	wire, err := hex.DecodeString("6172747851" + "0c000000" + "010100000000000100000000" + "89" + "0000")
	if err != nil {
		t.Fatalf("bad test hex: %v", err)
	}

	text, err := condition.Unmarshal(wire)
	if err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if !strings.Contains(text, "{") || !strings.Contains(text, "}") {
		t.Fatalf("Member_of operand not brace-wrapped: %q", text)
	}

	// The serialized text must now be re-parseable (previously errored).
	bin, err := condition.Marshal(text)
	if err != nil {
		t.Fatalf("Marshal(%q) error = %v (serialized text is not re-parseable)", text, err)
	}
	// And it must be stable from here on.
	text2, err := condition.Unmarshal(bin)
	if err != nil {
		t.Fatalf("re-Unmarshal error = %v", err)
	}
	if text != text2 {
		t.Fatalf("text round-trip not stable: %q vs %q", text, text2)
	}
}

// TestNegativeHexOctal_PreservesBase is a regression test for negative hex/octal
// integer literals serializing as decimal, which lost the base byte on the
// text round-trip.
func TestNegativeHexOctal_PreservesBase(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{`(@User.count==-0x5)`, "-0x5"},
		{`(@User.count==-010)`, "-010"},
		{`(@User.count==0x1f)`, "0x1f"},
		{`(@User.n==-5)`, "-5"},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			bin1, err := condition.Marshal(tc.expr)
			if err != nil {
				t.Fatalf("Marshal error = %v", err)
			}
			text, err := condition.Unmarshal(bin1)
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}
			if !strings.Contains(text, tc.want) {
				t.Fatalf("serialized %q, want it to contain %q", text, tc.want)
			}
			// Binary round-trip via text must be byte-stable (base byte preserved).
			bin2, err := condition.Marshal(text)
			if err != nil {
				t.Fatalf("re-Marshal error = %v", err)
			}
			if hex.EncodeToString(bin1) != hex.EncodeToString(bin2) {
				t.Fatalf("base byte not preserved through text round-trip for %q:\n  %x\n  %x", tc.expr, bin1, bin2)
			}
		})
	}
}
