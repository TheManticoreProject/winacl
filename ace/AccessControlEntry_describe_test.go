package ace_test

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/ace/condition"
	"github.com/TheManticoreProject/winacl/ace/resourceattribute"
)

// captureStdout runs f and returns everything it wrote to os.Stdout.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	f()
	w.Close()
	os.Stdout = orig
	return <-done
}

// TestDescribe_ApplicationData_Conditional verifies the ApplicationData subtree
// shows the artx magic bytes and the decoded conditional expression.
func TestDescribe_ApplicationData_Conditional(t *testing.T) {
	appData, err := condition.Marshal(`(@User.Title=="PM" && @User.Division=="Finance")`)
	if err != nil {
		t.Fatalf("condition.Marshal error = %v", err)
	}

	a := &ace.AccessControlEntry{}
	a.Header.Type.Value = acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK
	a.Identity.SID.FromString("S-1-1-0")
	a.ApplicationData.RawBytes = appData

	out := captureStdout(t, func() { a.Describe(0) })

	for _, want := range []string{
		"<ApplicationData>",
		"Conditional Expression",
		"Signature",
		"0x61727478", // "artx" magic bytes
		"artx",
		`@User.Title == "PM"`,
		`@User.Division == "Finance"`,
		"RawBytes",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("Describe output missing %q:\n%s", want, out)
		}
	}
}

// TestDescribe_ApplicationData_ResourceAttribute verifies the subtree shows the
// decoded CLAIM resource attribute.
func TestDescribe_ApplicationData_ResourceAttribute(t *testing.T) {
	appData, err := resourceattribute.Marshal(`"Project",TS,0,"Windows","SQL"`)
	if err != nil {
		t.Fatalf("resourceattribute.Marshal error = %v", err)
	}

	a := &ace.AccessControlEntry{}
	a.Header.Type.Value = acetype.ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE
	a.Identity.SID.FromString("S-1-1-0")
	a.ApplicationData.RawBytes = appData

	out := captureStdout(t, func() { a.Describe(0) })

	for _, want := range []string{
		"<ApplicationData>",
		"Resource Attribute",
		`"Project"`,
		"TS",
		`"Windows"`,
		`"SQL"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("Describe output missing %q:\n%s", want, out)
		}
	}
}

// TestDescribe_ApplicationData_Raw verifies non-conditional/non-RA data falls
// back to a raw-bytes line.
func TestDescribe_ApplicationData_Raw(t *testing.T) {
	a := &ace.AccessControlEntry{}
	a.Header.Type.Value = acetype.ACE_TYPE_SYSTEM_SCOPED_POLICY_ID
	a.Identity.SID.FromString("S-1-1-0")
	a.ApplicationData.RawBytes = []byte{0xde, 0xad, 0xbe, 0xef}

	out := captureStdout(t, func() { a.Describe(0) })

	if !strings.Contains(out, "<ApplicationData>") || !strings.Contains(out, "deadbeef") {
		t.Fatalf("Describe output missing raw ApplicationData subtree:\n%s", out)
	}
}
