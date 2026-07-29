package securitydescriptor

import (
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/ace/condition"
)

// TestConditionalACE_SDDLRoundTrip verifies that a conditional (callback) ACE's
// conditional expression survives an SDDL parse and re-serialize, and a full
// binary Marshal/Unmarshal round-trip. Previously the conditional-expression
// field was dropped on both parse and serialize.
func TestConditionalACE_SDDLRoundTrip(t *testing.T) {
	const sddl = `D:(XA;;GA;;;S-1-1-0;(@User.Title=="PM" && (@User.Division=="Finance" || @User.Division=="Sales")))`

	ntsd := &NtSecurityDescriptor{}
	if _, err := ntsd.FromSDDLString(sddl); err != nil {
		t.Fatalf("FromSDDLString error = %v", err)
	}

	if ntsd.DACL == nil || len(ntsd.DACL.Entries) != 1 {
		t.Fatalf("expected exactly one DACL entry, got %+v", ntsd.DACL)
	}
	ace := ntsd.DACL.Entries[0]

	if ace.Header.Type.Value != acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK {
		t.Fatalf("ACE type = 0x%02x, want ACCESS_ALLOWED_CALLBACK (0x09)", ace.Header.Type.Value)
	}
	if !condition.IsConditional(ace.ApplicationData.RawBytes) {
		t.Fatalf("ACE ApplicationData is not a conditional expression: %x", ace.ApplicationData.RawBytes)
	}

	// The conditional expression must be preserved in the SDDL round-trip.
	out, err := ntsd.ToSDDLString()
	if err != nil {
		t.Fatalf("ToSDDLString error = %v", err)
	}
	for _, want := range []string{`XA;`, `@User.Title == "PM"`, `@User.Division == "Finance"`, `@User.Division == "Sales"`, `||`, `&&`} {
		if !strings.Contains(out, want) {
			t.Fatalf("ToSDDLString output missing %q:\n  %s", want, out)
		}
	}

	// Re-parsing the serialized SDDL must yield the same ApplicationData bytes.
	ntsd2 := &NtSecurityDescriptor{}
	if _, err := ntsd2.FromSDDLString(out); err != nil {
		t.Fatalf("re-FromSDDLString(%q) error = %v", out, err)
	}
	got := ntsd2.DACL.Entries[0].ApplicationData.RawBytes
	if string(got) != string(ace.ApplicationData.RawBytes) {
		t.Fatalf("conditional expression not stable across SDDL round-trip:\n  first:  %x\n  second: %x", ace.ApplicationData.RawBytes, got)
	}

	// Full binary round-trip: Marshal -> Unmarshal must preserve the condition.
	bin, err := ntsd.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	parsed := &NtSecurityDescriptor{}
	if _, err := parsed.Unmarshal(bin); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if parsed.DACL == nil || len(parsed.DACL.Entries) != 1 {
		t.Fatalf("binary round-trip lost the ACE")
	}
	if string(parsed.DACL.Entries[0].ApplicationData.RawBytes) != string(ace.ApplicationData.RawBytes) {
		t.Fatalf("conditional expression not preserved across binary round-trip:\n  before: %x\n  after:  %x",
			ace.ApplicationData.RawBytes, parsed.DACL.Entries[0].ApplicationData.RawBytes)
	}
}

// TestObjectCallbackACE_ZD_SDDLRoundTrip verifies that a ZD object-deny callback
// ACE (ACCESS_DENIED_CALLBACK_OBJECT, 0x0C) round-trips through SDDL and binary,
// preserving its type, ObjectType GUID scope, and conditional expression.
// Previously ZD had no SDDL mapping: parsing failed and ToSDDLString dropped it.
func TestObjectCallbackACE_ZD_SDDLRoundTrip(t *testing.T) {
	const objectGUID = "bf967950-0de6-11d0-a285-00aa003049e2"
	const sddl = `D:P(ZD;;WP;bf967950-0de6-11d0-a285-00aa003049e2;;S-1-1-0;(Member_of {SID(BA)}))`

	ntsd := &NtSecurityDescriptor{}
	if _, err := ntsd.FromSDDLString(sddl); err != nil {
		t.Fatalf("FromSDDLString error = %v", err)
	}
	if ntsd.DACL == nil || len(ntsd.DACL.Entries) != 1 {
		t.Fatalf("expected exactly one DACL entry, got %+v", ntsd.DACL)
	}
	ace := ntsd.DACL.Entries[0]

	if ace.Header.Type.Value != acetype.ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT {
		t.Fatalf("ACE type = 0x%02x, want ACCESS_DENIED_CALLBACK_OBJECT (0x0c)", ace.Header.Type.Value)
	}
	if !condition.IsConditional(ace.ApplicationData.RawBytes) {
		t.Fatalf("ACE ApplicationData is not a conditional expression: %x", ace.ApplicationData.RawBytes)
	}
	if got := ace.AccessControlObjectType.ObjectType.GUID.ToFormatD(); got != objectGUID {
		t.Fatalf("ObjectType GUID = %q, want %q", got, objectGUID)
	}

	// The type (ZD), GUID and condition must survive SDDL re-serialization.
	out, err := ntsd.ToSDDLString()
	if err != nil {
		t.Fatalf("ToSDDLString error = %v", err)
	}
	for _, want := range []string{`ZD;`, objectGUID, `Member_of`, `SID(S-1-5-32-544)`} {
		if !strings.Contains(out, want) {
			t.Fatalf("ToSDDLString output missing %q:\n  %s", want, out)
		}
	}

	// Re-parsing the serialized SDDL must yield the same ApplicationData bytes.
	ntsd2 := &NtSecurityDescriptor{}
	if _, err := ntsd2.FromSDDLString(out); err != nil {
		t.Fatalf("re-FromSDDLString(%q) error = %v", out, err)
	}
	if string(ntsd2.DACL.Entries[0].ApplicationData.RawBytes) != string(ace.ApplicationData.RawBytes) {
		t.Fatalf("condition not stable across SDDL round-trip:\n  first:  %x\n  second: %x",
			ace.ApplicationData.RawBytes, ntsd2.DACL.Entries[0].ApplicationData.RawBytes)
	}

	// Full binary round-trip must preserve type, GUID and condition.
	bin, err := ntsd.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	parsed := &NtSecurityDescriptor{}
	if _, err := parsed.Unmarshal(bin); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if parsed.DACL == nil || len(parsed.DACL.Entries) != 1 {
		t.Fatalf("binary round-trip lost the ACE")
	}
	pace := parsed.DACL.Entries[0]
	if pace.Header.Type.Value != acetype.ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT {
		t.Fatalf("binary round-trip type = 0x%02x, want 0x0c", pace.Header.Type.Value)
	}
	if got := pace.AccessControlObjectType.ObjectType.GUID.ToFormatD(); got != objectGUID {
		t.Fatalf("binary round-trip GUID = %q, want %q", got, objectGUID)
	}
	if string(pace.ApplicationData.RawBytes) != string(ace.ApplicationData.RawBytes) {
		t.Fatalf("condition not preserved across binary round-trip:\n  before: %x\n  after:  %x",
			ace.ApplicationData.RawBytes, pace.ApplicationData.RawBytes)
	}
}

// TestConditionalACE_RejectedOnNonCallback verifies a conditional expression on
// a non-callback ACE type is rejected rather than silently mishandled.
func TestConditionalACE_RejectedOnNonCallback(t *testing.T) {
	const sddl = `D:(A;;FX;;;S-1-1-0;(@User.Title=="PM"))`
	ntsd := &NtSecurityDescriptor{}
	if _, err := ntsd.FromSDDLString(sddl); err == nil {
		t.Fatal("expected an error for a conditional expression on a non-callback ACE type, got nil")
	}
}

// TestACEType_TL_FL_RoundTrip is a regression test for the SDDL ACE types TL
// (SYSTEM_PROCESS_TRUST_LABEL, 0x14) and FL (SYSTEM_ACCESS_FILTER, 0x15). Their
// SDDL constants were declared but their SDDLToACETypeMap entries were commented
// out because the ACE type constants did not exist, so both were rejected with
// "unknown ACE type".
//
// Both carry an ACCESS_MASK followed by a SID, the same wire shape as
// SYSTEM_MANDATORY_LABEL and SYSTEM_SCOPED_POLICY_ID.
func TestACEType_TL_FL_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		sddl string
		want uint8
	}{
		{"TL", "S:(TL;;;;;WD)", acetype.ACE_TYPE_SYSTEM_PROCESS_TRUST_LABEL},
		{"FL", "S:(FL;;;;;WD)", acetype.ACE_TYPE_SYSTEM_ACCESS_FILTER},
		{"TL with mask", "S:(TL;;CCDC;;;WD)", acetype.ACE_TYPE_SYSTEM_PROCESS_TRUST_LABEL},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sd := &NtSecurityDescriptor{}
			if _, err := sd.FromSDDLString(c.sddl); err != nil {
				t.Fatalf("FromSDDLString(%q) error = %v", c.sddl, err)
			}
			if sd.SACL == nil || len(sd.SACL.Entries) != 1 {
				t.Fatalf("expected exactly one SACL entry")
			}
			if got := sd.SACL.Entries[0].Header.Type.Value; got != c.want {
				t.Fatalf("ACE type = 0x%02x, want 0x%02x", got, c.want)
			}

			// Binary round-trip: the Marshal/Unmarshal switches must handle the
			// type too, not just the SDDL mapping.
			raw, err := sd.Marshal()
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			back := &NtSecurityDescriptor{}
			if _, err := back.Unmarshal(raw); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			got, err := back.ToSDDLString()
			if err != nil {
				t.Fatalf("ToSDDLString() error = %v", err)
			}
			if got != c.sddl {
				t.Fatalf("round-trip = %q, want %q", got, c.sddl)
			}
		})
	}
}

// TestACEType_TL_FL_Names pins the constant values and their human-readable names.
func TestACEType_TL_FL_Names(t *testing.T) {
	if acetype.ACE_TYPE_SYSTEM_PROCESS_TRUST_LABEL != 0x14 {
		t.Errorf("ACE_TYPE_SYSTEM_PROCESS_TRUST_LABEL = 0x%02x, want 0x14",
			acetype.ACE_TYPE_SYSTEM_PROCESS_TRUST_LABEL)
	}
	if acetype.ACE_TYPE_SYSTEM_ACCESS_FILTER != 0x15 {
		t.Errorf("ACE_TYPE_SYSTEM_ACCESS_FILTER = 0x%02x, want 0x15",
			acetype.ACE_TYPE_SYSTEM_ACCESS_FILTER)
	}
	for value, want := range map[uint8]string{
		0x14: "SYSTEM_PROCESS_TRUST_LABEL",
		0x15: "SYSTEM_ACCESS_FILTER",
	} {
		at := acetype.AccessControlEntryType{Value: value}
		if got := at.String(); got == "" {
			t.Errorf("AccessControlEntryType{0x%02x}.String() is empty, want it to name %s", value, want)
		}
	}
}
