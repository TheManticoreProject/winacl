package describe_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/utils/describe"
)

// TestNest prefixes each line with exactly one indentation unit.
func TestNest(t *testing.T) {
	in := []string{"<A>", " │ x : 1", " └─"}
	got := describe.Nest(in)

	if len(got) != len(in) {
		t.Fatalf("Nest changed line count: got %d, want %d", len(got), len(in))
	}
	for i := range got {
		want := describe.Unit + in[i]
		if got[i] != want {
			t.Fatalf("Nest[%d] = %q, want %q", i, got[i], want)
		}
	}

	// Nest must not mutate its input.
	if in[0] != "<A>" {
		t.Fatalf("Nest mutated its input: %q", in[0])
	}
}

// TestWithCallback prepends indent levels and routes each line to the callback
// with a trailing newline.
func TestWithCallback(t *testing.T) {
	lines := []string{"<A>", " └─"}
	var got []string
	describe.WithCallback(2, lines, func(format string, a ...any) (int, error) {
		got = append(got, strings.TrimSuffix(fmt.Sprintf(format, a...), "\n"))
		return 0, nil
	})

	prefix := strings.Repeat(describe.Unit, 2)
	want := []string{prefix + "<A>", prefix + " └─"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("WithCallback produced:\n%v\nwant:\n%v", got, want)
	}
}
