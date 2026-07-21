package applicationdata_test

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/ace/applicationdata"
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

// TestUnmarshalMarshalRoundTrip verifies that Marshal(Unmarshal(x)) == x and
// that Unmarshal keeps a private copy of the payload rather than aliasing the
// caller's buffer.
func TestUnmarshalMarshalRoundTrip(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef}

	ad := &applicationdata.ApplicationData{}
	n, err := ad.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if n != len(raw) {
		t.Fatalf("Unmarshal consumed %d bytes, want %d", n, len(raw))
	}
	if ad.Len() != len(raw) || ad.RawBytesSize != uint32(len(raw)) {
		t.Fatalf("Len = %d / RawBytesSize = %d, want %d", ad.Len(), ad.RawBytesSize, len(raw))
	}

	// Mutating the source buffer must not affect the stored payload.
	raw[0] = 0x00
	out, err := ad.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	if !bytes.Equal(out, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("Marshal aliased the caller's buffer, got %x", out)
	}
}

// TestEqual verifies byte-wise comparison with nil/empty treated as equal.
func TestEqual(t *testing.T) {
	a := &applicationdata.ApplicationData{RawBytes: []byte{1, 2, 3}}
	b := &applicationdata.ApplicationData{RawBytes: []byte{1, 2, 3}}
	c := &applicationdata.ApplicationData{RawBytes: []byte{1, 2, 4}}
	empty := &applicationdata.ApplicationData{}
	nilData := &applicationdata.ApplicationData{RawBytes: nil}

	if !a.Equal(b) {
		t.Error("expected identical payloads to be equal")
	}
	if a.Equal(c) {
		t.Error("expected differing payloads to be unequal")
	}
	if !empty.Equal(nilData) {
		t.Error("expected nil and empty payloads to be equal")
	}
}

// TestDescribeConditional verifies the conditional-expression subtree.
func TestDescribeConditional(t *testing.T) {
	raw, err := condition.Marshal(`(@User.Title=="PM")`)
	if err != nil {
		t.Fatalf("condition.Marshal error = %v", err)
	}
	ad := &applicationdata.ApplicationData{AceType: acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK}
	ad.Unmarshal(raw)

	if !ad.IsConditional() {
		t.Fatal("expected IsConditional to be true")
	}

	out := captureStdout(t, func() { ad.Describe(0) })
	for _, want := range []string{"<ApplicationData>", "Conditional Expression", "0x61727478", `@User.Title == "PM"`, "RawBytes"} {
		if !strings.Contains(out, want) {
			t.Fatalf("Describe output missing %q:\n%s", want, out)
		}
	}
}

// TestDescribeResourceAttribute verifies the resource-attribute subtree, which
// is selected by the owning ACE type.
func TestDescribeResourceAttribute(t *testing.T) {
	raw, err := resourceattribute.Marshal(`"Project",TS,0,"Windows"`)
	if err != nil {
		t.Fatalf("resourceattribute.Marshal error = %v", err)
	}
	ad := &applicationdata.ApplicationData{AceType: acetype.ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE}
	ad.Unmarshal(raw)

	if !ad.IsResourceAttribute() {
		t.Fatal("expected IsResourceAttribute to be true")
	}

	out := captureStdout(t, func() { ad.Describe(0) })
	for _, want := range []string{"<ApplicationData>", "Resource Attribute", `"Project"`, "TS", `"Windows"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("Describe output missing %q:\n%s", want, out)
		}
	}
}

// TestDescribeRaw verifies non-conditional/non-RA data falls back to raw bytes.
func TestDescribeRaw(t *testing.T) {
	ad := &applicationdata.ApplicationData{AceType: acetype.ACE_TYPE_SYSTEM_SCOPED_POLICY_ID}
	ad.Unmarshal([]byte{0xde, 0xad, 0xbe, 0xef})

	out := captureStdout(t, func() { ad.Describe(0) })
	if !strings.Contains(out, "<ApplicationData>") || !strings.Contains(out, "deadbeef") {
		t.Fatalf("Describe output missing raw subtree:\n%s", out)
	}
}
