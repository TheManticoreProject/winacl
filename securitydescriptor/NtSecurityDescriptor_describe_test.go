package securitydescriptor

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/utils/describe"
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

// sampleNTSD builds a security descriptor with an owner, group and a populated
// DACL so the describe tree exercises nesting through every layer.
func sampleNTSD(t *testing.T) *NtSecurityDescriptor {
	t.Helper()
	const sddl = `O:BAG:BAD:(A;;GA;;;S-1-1-0)(D;;GR;;;S-1-5-32-545)`
	ntsd := &NtSecurityDescriptor{}
	if _, err := ntsd.FromSDDLString(sddl); err != nil {
		t.Fatalf("FromSDDLString error = %v", err)
	}
	return ntsd
}

// TestDescribeLayeringConsistency verifies that Describe, DescribeWithCallback
// and DescribeList are three views of the same content: Describe(0) prints
// exactly the DescribeList lines each terminated by a newline, and
// DescribeWithCallback routes the same lines to a custom sink.
func TestDescribeLayeringConsistency(t *testing.T) {
	ntsd := sampleNTSD(t)

	lines := ntsd.DescribeList()
	if len(lines) == 0 {
		t.Fatal("DescribeList returned no lines")
	}

	// Describe(0) must equal every line joined with newlines (indent 0 adds no
	// prefix), with a trailing newline after the last line.
	want := strings.Join(lines, "\n") + "\n"
	got := captureStdout(t, func() { ntsd.Describe(0) })
	if got != want {
		t.Fatalf("Describe(0) output does not match DescribeList:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// DescribeWithCallback at indent 0 must deliver the same lines.
	var collected []string
	ntsd.DescribeWithCallback(0, func(format string, a ...any) (int, error) {
		collected = append(collected, strings.TrimSuffix(fmt.Sprintf(format, a...), "\n"))
		return 0, nil
	})
	if strings.Join(collected, "\n") != strings.Join(lines, "\n") {
		t.Fatalf("DescribeWithCallback lines differ from DescribeList:\n%v", collected)
	}
}

// TestDescribeIndentPrefix verifies that a non-zero indent prefixes every line
// with the expected number of indentation units.
func TestDescribeIndentPrefix(t *testing.T) {
	ntsd := sampleNTSD(t)
	lines := ntsd.DescribeList()

	out := captureStdout(t, func() { ntsd.Describe(2) })
	prefix := strings.Repeat(describe.Unit, 2) // two indentation units
	for _, got := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if !strings.HasPrefix(got, prefix) {
			t.Fatalf("line missing indent prefix %q: %q", prefix, got)
		}
	}
	if n := len(strings.Split(strings.TrimRight(out, "\n"), "\n")); n != len(lines) {
		t.Fatalf("Describe(2) emitted %d lines, DescribeList has %d", n, len(lines))
	}
}
