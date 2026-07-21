// Package describe provides the shared rendering primitives used by the
// Describe / DescribeList / DescribeWithCallback trio implemented on every
// winacl structure.
//
// Each structure exposes its output as a flat list of lines at indentation
// depth 0 via DescribeList(). Rendering (adding indentation and choosing where
// the text goes) is layered on top:
//
//	DescribeList()                -> []string, the lines at indent 0
//	DescribeWithCallback(indent,  -> prepends indent levels and routes each line
//	                     printf)      to a fmt.Printf-like callback
//	Describe(indent)              -> DescribeWithCallback(indent, fmt.Printf)
//
// A parent structure composes its own list from its children's by nesting each
// child's DescribeList() one level deeper with Nest.
package describe

import "strings"

// Unit is one level of indentation in the Describe tree output.
const Unit = " │ "

// Printf is the signature of a fmt.Printf-like sink. fmt.Printf satisfies it
// directly, as does any wrapper around fmt.Fprintf or a structured logger.
type Printf = func(format string, a ...any) (int, error)

// Nest prefixes each of the given lines with one indentation Unit. It is used to
// compose a parent's DescribeList from its children's DescribeList output.
func Nest(lines []string) []string {
	nested := make([]string, len(lines))
	for i, line := range lines {
		nested[i] = Unit + line
	}
	return nested
}

// WithCallback renders lines at the given indentation depth: it prepends indent
// copies of Unit to each line and routes the result (with a trailing newline) to
// printf.
func WithCallback(indent int, lines []string, printf Printf) {
	prefix := strings.Repeat(Unit, indent)
	for _, line := range lines {
		printf("%s%s\n", prefix, line)
	}
}
