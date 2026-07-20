package securitydescriptor

import (
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/ace/resourceattribute"
)

// TestResourceAttributeACE_SDDLRoundTrip verifies that a resource-attribute (RA)
// ACE's attribute-data survives an SDDL parse/serialize and a full binary
// Marshal/Unmarshal round-trip. Previously the attribute-data field was dropped.
func TestResourceAttributeACE_SDDLRoundTrip(t *testing.T) {
	const sddl = `S:(RA;;;;;S-1-1-0;("Project",TS,0,"Windows","SQL"))`

	ntsd := &NtSecurityDescriptor{}
	if _, err := ntsd.FromSDDLString(sddl); err != nil {
		t.Fatalf("FromSDDLString error = %v", err)
	}
	if ntsd.SACL == nil || len(ntsd.SACL.Entries) != 1 {
		t.Fatalf("expected one SACL entry, got %+v", ntsd.SACL)
	}
	ace := ntsd.SACL.Entries[0]
	if ace.Header.Type.Value != acetype.ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE {
		t.Fatalf("ACE type = 0x%02x, want SYSTEM_RESOURCE_ATTRIBUTE (0x12)", ace.Header.Type.Value)
	}
	if len(ace.ApplicationData) == 0 {
		t.Fatal("resource attribute ApplicationData is empty")
	}

	// The attribute data must decode to the expected fields.
	ra, err := resourceattribute.Decode(ace.ApplicationData)
	if err != nil {
		t.Fatalf("Decode error = %v", err)
	}
	if ra.Name != "Project" || len(ra.Strings) != 2 {
		t.Fatalf("decoded attribute = %+v, want name Project with 2 strings", ra)
	}

	// SDDL round-trip preserves the attribute.
	out, err := ntsd.ToSDDLString()
	if err != nil {
		t.Fatalf("ToSDDLString error = %v", err)
	}
	for _, want := range []string{`RA;`, `"Project"`, `TS`, `"Windows"`, `"SQL"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("ToSDDLString output missing %q:\n  %s", want, out)
		}
	}

	ntsd2 := &NtSecurityDescriptor{}
	if _, err := ntsd2.FromSDDLString(out); err != nil {
		t.Fatalf("re-FromSDDLString(%q) error = %v", out, err)
	}
	if string(ntsd2.SACL.Entries[0].ApplicationData) != string(ace.ApplicationData) {
		t.Fatalf("attribute data not stable across SDDL round-trip:\n  first:  %x\n  second: %x",
			ace.ApplicationData, ntsd2.SACL.Entries[0].ApplicationData)
	}

	// Full binary round-trip.
	bin, err := ntsd.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	parsed := &NtSecurityDescriptor{}
	if _, err := parsed.Unmarshal(bin); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if string(parsed.SACL.Entries[0].ApplicationData) != string(ace.ApplicationData) {
		t.Fatalf("attribute data not preserved across binary round-trip")
	}
}
