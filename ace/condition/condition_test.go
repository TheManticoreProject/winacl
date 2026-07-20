package condition_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/ace/condition"
)

// TestMarshal_KnownAnswer validates the encoder against the exact byte sequence
// from MS-DTYP 2.4.4.17.2 Example 1 for the conditional expression (Title=="VP").
func TestMarshal_KnownAnswer(t *testing.T) {
	const expr = `(Title=="VP")`
	// artx | f8 local-attr len=10 "Title" | 10 unicode len=4 "VP" | 80 == | 00 00 00 pad
	want := "61727478" +
		"f80a000000" + "540069007400 6c006500" +
		"10" + "04000000" + "560050 00" +
		"80" +
		"000000"
	want = strings.ReplaceAll(want, " ", "")

	got, err := condition.Marshal(expr)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != want {
		t.Fatalf("Marshal(%q) =\n  %s\nwant\n  %s", expr, gotHex, want)
	}
	if len(got)%4 != 0 {
		t.Fatalf("encoded length %d is not DWORD-aligned", len(got))
	}
}

// TestUnmarshal_KnownAnswer validates the decoder against the same example.
func TestUnmarshal_KnownAnswer(t *testing.T) {
	raw, _ := hex.DecodeString("61727478f80a000000540069007400" + "6c006500" + "1004000000560050008000" + "0000")
	got, err := condition.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got != `Title == "VP"` {
		t.Fatalf("Unmarshal() = %q, want %q", got, `Title == "VP"`)
	}
}

// TestRoundTrip_Binary verifies that Marshal->Unmarshal->Marshal is stable for a
// range of expressions covering every operator/literal/attribute form.
func TestRoundTrip_Binary(t *testing.T) {
	exprs := []string{
		`(Title=="VP")`,
		`(@User.Title=="PM")`,
		`(@User.Title=="PM" && @User.Division=="Finance")`,
		`(@User.Title=="PM" && (@User.Division=="Finance" || @User.Division=="Sales"))`,
		`(@User.smartcard==1 || @Device.managed==1)`,
		`(@Resource.dept Any_of {"Sales", "HR"})`,
		`(@User.clearanceLevel>=@Resource.requiredClearance)`,
		`(Member_of {SID(BA)})`,
		`(Member_of {SID(BA), SID(WD)})`,
		`(Not_Member_of_Any {SID(BA)})`,
		`(Exists @User.Title)`,
		`(Not_Exists @User.Title)`,
		`(!(@User.Title=="PM"))`,
		`(@User.count>=-5)`,
		`(@User.count==0x1f)`,
		`(@User.blob==#01ff2a)`,
		`(@User.dept Contains "Sales")`,
		`(@User.dept != {1, 2, 3})`,
	}

	for _, expr := range exprs {
		t.Run(expr, func(t *testing.T) {
			bin1, err := condition.Marshal(expr)
			if err != nil {
				t.Fatalf("Marshal(%q) error = %v", expr, err)
			}
			if !condition.IsConditional(bin1) {
				t.Fatalf("encoded data lacks the artx signature")
			}
			text, err := condition.Unmarshal(bin1)
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}
			bin2, err := condition.Marshal(text)
			if err != nil {
				t.Fatalf("re-Marshal(%q) error = %v", text, err)
			}
			if hex.EncodeToString(bin1) != hex.EncodeToString(bin2) {
				t.Fatalf("binary round-trip not stable for %q:\n  first:  %x\n  via %q\n  second: %x", expr, bin1, text, bin2)
			}
		})
	}
}

// TestParseErrors verifies malformed expressions are rejected.
func TestParseErrors(t *testing.T) {
	bad := []string{
		`(@User.Title ==)`,
		`(&& @User.Title=="x")`,
		`(@User.Title == "unterminated)`,
		`(Member_of SID(BA))`, // Member_of requires a brace array
		`()`,
	}
	for _, expr := range bad {
		t.Run(expr, func(t *testing.T) {
			if _, err := condition.Marshal(expr); err == nil {
				t.Fatalf("Marshal(%q) expected an error, got nil", expr)
			}
		})
	}
}

// TestIsConditional checks signature detection.
func TestIsConditional(t *testing.T) {
	if condition.IsConditional([]byte{0x00, 0x01, 0x02, 0x03}) {
		t.Error("non-artx data reported as conditional")
	}
	if !condition.IsConditional([]byte("artx....")) {
		t.Error("artx data not reported as conditional")
	}
	if condition.IsConditional([]byte{0x61, 0x72}) {
		t.Error("short data reported as conditional")
	}
}
