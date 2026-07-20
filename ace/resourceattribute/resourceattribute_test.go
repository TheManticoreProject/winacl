package resourceattribute_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace/resourceattribute"
)

// TestRoundTrip verifies Marshal -> Unmarshal -> Marshal is byte-stable and the
// decoded text matches expectations for each resource-attribute value type.
func TestRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"string-multi", `"Project",TS,0,"Windows","SQL"`},
		{"string-single", `"Dept",TS,0,"Finance"`},
		{"uint", `"Secrecy",TU,0,3`},
		{"int-negative", `"Offset",TI,0,-5`},
		{"int-multi", `"Levels",TI,0,1,2,3`},
		{"bool", `"Enabled",TB,0,1`},
		{"bool-false", `"Enabled",TB,0,0`},
		{"octet", `"Blob",TX,0,#01ff2a`},
		{"sid", `"Owner",TD,0,S-1-1-0`},
		{"flags-hex", `"Marked",TU,0x10,7`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin1, err := resourceattribute.Marshal(tc.text)
			if err != nil {
				t.Fatalf("Marshal(%q) error = %v", tc.text, err)
			}
			if len(bin1)%4 != 0 {
				t.Fatalf("encoding not DWORD-aligned (%d bytes)", len(bin1))
			}
			text, err := resourceattribute.Unmarshal(bin1)
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}
			bin2, err := resourceattribute.Marshal(text)
			if err != nil {
				t.Fatalf("re-Marshal(%q) error = %v", text, err)
			}
			if string(bin1) != string(bin2) {
				t.Fatalf("binary round-trip not stable for %q:\n  first:  %x\n  via %q\n  second: %x", tc.text, bin1, text, bin2)
			}
		})
	}
}

// TestParsedFields checks the decoded structure of a known attribute.
func TestParsedFields(t *testing.T) {
	ra, err := resourceattribute.Parse(`("Project",TS,0,"Windows","SQL")`)
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}
	if ra.Name != "Project" {
		t.Errorf("Name = %q, want Project", ra.Name)
	}
	if ra.ValueType != resourceattribute.TypeString {
		t.Errorf("ValueType = 0x%04x, want TypeString", ra.ValueType)
	}
	if len(ra.Strings) != 2 || ra.Strings[0] != "Windows" || ra.Strings[1] != "SQL" {
		t.Errorf("Strings = %v, want [Windows SQL]", ra.Strings)
	}
}

// TestParseErrors verifies malformed attribute data is rejected.
func TestParseErrors(t *testing.T) {
	bad := []string{
		`"Name"`,             // missing type and flags
		`"Name",TZ,0,1`,      // unknown type
		`"Name",TB,0,2`,      // invalid boolean
		`Name,TS,0,"x"`,      // unquoted name
		`"Name",TI,0,notint`, // invalid integer
	}
	for _, s := range bad {
		if _, err := resourceattribute.Marshal(s); err == nil {
			t.Errorf("Marshal(%q) expected an error, got nil", s)
		}
	}
}
