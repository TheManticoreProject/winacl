---
name: describe-pattern
description: >-
  Implement or refactor a Go structure's human-readable tree output using the
  three-layer Describe pattern: DescribeList() []string (content), 
  DescribeWithCallback(indent, printf) (rendering + sink), and Describe(indent)
  (stdout convenience). Use whenever adding a Describe method to a new struct,
  converting an existing Describe(indent int) that prints directly with
  fmt.Printf/strings.Repeat, making describe output capturable/redirectable, or
  keeping a project's Describe methods consistent. Triggers: "add a Describe
  method", "refactor Describe", "DescribeList", "make the tree output
  capturable", "describe pattern".
---

# Describe pattern

Apply this when a Go structure must render itself as an indented,
human-readable tree **and** expose that content as data (so callers can capture,
redirect, or compose it). It separates three concerns: **what** the lines are,
**how deep** they are indented, and **where** they go.

## The contract

Every describable type implements the same trio, with a strict one-way
dependency:

```
Describe(indent)  ──calls──▶  DescribeWithCallback(indent, describe.Printfln)  ──iterates──▶  DescribeList()
```

```go
// 1. Content — the lines at indentation depth 0. Source of truth.
func (t *T) DescribeList() []string

// 2. Rendering + sink — indent each line and route it to a fmt.Printf-like callback.
func (t *T) DescribeWithCallback(indent int, printf describe.Printf)

// 3. Convenience — print to stdout. Unchanged public behavior.
func (t *T) Describe(indent int)
```

- `DescribeList()` is the **only** place that knows the content.
- `DescribeWithCallback` is the **only** place that adds indentation. It emits
  each line **bare** (no trailing newline) and lets the callback decide
  termination.
- `Describe` is a one-liner that picks `describe.Printfln` as the sink — a
  stdout sink that appends the newline.

New output behavior (buffer, logger, `io.Writer`) never touches a type — the
caller supplies a different callback.

## Step 1 — Ensure the helper package exists

Shared logic lives in one package (e.g. `utils/describe`) so per-type methods
stay tiny and identical. Create it if absent:

```go
package describe

import (
	"fmt"
	"strings"
)

// Unit is one level of indentation in the tree output.
const Unit = " │ "

// Printf is the signature of a fmt.Printf-like sink. fmt.Printf satisfies it
// directly, as does any wrapper around fmt.Fprintf or a structured logger.
type Printf = func(format string, a ...any) (int, error)

// Printfln is the default Describe sink: a Printf-compatible callback that
// writes to stdout and appends a trailing newline. WithCallback emits bare
// lines, so the sink decides how each line is terminated.
func Printfln(format string, a ...any) (int, error) {
	return fmt.Printf(format+"\n", a...)
}

// Nest prefixes each of the given lines with one indentation Unit. Used to
// compose a parent's DescribeList from its children's.
func Nest(lines []string) []string {
	nested := make([]string, len(lines))
	for i, line := range lines {
		nested[i] = Unit + line
	}
	return nested
}

// WithCallback renders lines at the given depth: it prepends indent copies of
// Unit to each line and routes the result to printf. Lines are emitted bare,
// without a trailing newline; the callback decides termination.
func WithCallback(indent int, lines []string, printf Printf) {
	prefix := strings.Repeat(Unit, indent)
	for _, line := range lines {
		printf("%s%s", prefix, line)
	}
}
```

Hold these invariants:

- **`Unit` is the single source of indentation.** Never hand-write `" │ "`
  prefixes except for a line intrinsically one level deeper than its siblings.
- **`DescribeList()` lines carry no outer indentation** — always depth 0.
  Indentation is applied exactly once, at render time, by `WithCallback`.
- **`WithCallback` emits bare lines** (no trailing newline). Termination is the
  sink's job: `Describe` uses `Printfln` for stdout; a buffer/logger sink adds
  whatever terminator it wants.
- **Pass line text as an argument**, never as the format string
  (`printf("%s%s", prefix, line)`), so a `%` inside a line is never interpreted.

## Step 2 — Write `DescribeList` for the type

Pick the recipe matching the shape.

### Leaf type

Opening tag, one `fmt.Sprintf` per field line (each starting with `" │ "`),
closing `" └─"`:

```go
func (m *AccessControlMask) DescribeList() []string {
	return []string{
		"<AccessControlMask>",
		fmt.Sprintf(" │ \x1b[93mMask\x1b[0m : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)", m.RawValue, m.String()),
		" └─",
	}
}
```

### Composite type

Splice in each child's `DescribeList()` one level deeper via `describe.Nest`:

```go
func (sacl *SystemAccessControlList) DescribeList() []string {
	lines := []string{"<SystemAccessControlList>"}
	lines = append(lines, describe.Nest(sacl.Header.DescribeList())...)
	for _, ace := range sacl.Entries {
		lines = append(lines, describe.Nest(ace.DescribeList())...)
	}
	lines = append(lines, " └─")
	return lines
}
```

### Child two levels deep (wrapper subtree)

Build the wrapper as its own list, then `Nest` the whole thing once:

```go
if ntsd.Owner != nil {
	owner := []string{"<Owner>"}
	owner = append(owner, describe.Nest(ntsd.Owner.DescribeList())...) // SID one level under <Owner>
	owner = append(owner, " └─")
	lines = append(lines, describe.Nest(owner)...)                     // whole block one level under root
}
```

### Single line one level deeper than its siblings

Prefix that one line with `describe.Unit` directly:

```go
lines = append(lines, fmt.Sprintf(" │ \x1b[93mSubAuthorities (%03d)\x1b[0m :", sid.SubAuthorityCount))
for index, sub := range sid.SubAuthorities {
	lines = append(lines, describe.Unit+fmt.Sprintf(" │ \x1b[93mSubAuthority %02d\x1b[0m   : \x1b[96m0x%08x\x1b[0m (\x1b[94m%d\x1b[0m)", index, sub, sub))
}
lines = append(lines, describe.Unit+" └─")
```

### Conditionals and loops

`DescribeList` is ordinary Go. Branch and loop freely; `append` lines (and
`Nest`ed child lists) instead of printing.

## Step 3 — Add the two boilerplate methods

Identical for every type:

```go
func (t *T) DescribeWithCallback(indent int, printf describe.Printf) {
	describe.WithCallback(indent, t.DescribeList(), printf)
}

func (t *T) Describe(indent int) {
	t.DescribeWithCallback(indent, describe.Printfln)
}
```

## Converting an existing `Describe`

For a `Describe(indent int)` that used `indentPrompt := strings.Repeat(" │ ", indent)`:

| Old (inside `Describe`)                                   | New (inside `DescribeList`)                              |
|-----------------------------------------------------------|----------------------------------------------------------|
| `fmt.Printf("%s…\n", indentPrompt, args…)`                | `append(lines, fmt.Sprintf("…", args…))`                 |
| line built with `strings.Repeat(" │ ", indent+1)`         | `append(lines, describe.Unit + fmt.Sprintf("…", …))`     |
| `child.Describe(indent + 1)`                              | `append(lines, describe.Nest(child.DescribeList())...)`  |
| `child.Describe(indent + 2)`                              | nest twice, or build the wrapper subtree and `Nest` once |
| a static line (no format args)                            | append a plain string literal (avoid `Sprintf` with no verbs) |

After converting, remove the now-unused `strings` import if nothing else uses it,
and add the `describe` import.

## Conventions

- **Tag line:** `"<TypeName>"` opens a block; `" └─"` closes it — both are
  content lines, not rendering artifacts.
- **Field line:** `" │ "` + label + value, keeping ANSI color escapes
  (`\x1b[93m…\x1b[0m`) as part of the string. Colors are content; stripping them
  is a sink-side concern.
- **Keep `DescribeList` read-only** on the receiver where possible (propagating a
  known type tag into a child before describing it is acceptable).

## Verify

Output must be **byte-identical** at the top-level call. The identity to assert:

```
Describe(0) output  ==  strings.Join(DescribeList(), "\n") + "\n"
```

and, for any indent, every emitted line begins with
`strings.Repeat(describe.Unit, indent)`.

> A type whose old `Describe` printed its root at column 0 regardless of `indent`
> becomes uniform here — the root is indented like everything else, observable
> only at `indent > 0`, never at `Describe(0)`.

Cover with tests (a representative leaf and composite is enough):

1. `Describe(0)` equals `strings.Join(DescribeList(), "\n") + "\n"`.
2. `DescribeWithCallback(0, sink)` delivers the same lines as `DescribeList()`.
3. At `indent = n > 0`, every line is prefixed with `strings.Repeat(describe.Unit, n)`.
4. Helper units: `Nest` prefixes exactly one `Unit` and does not mutate its
   input; `WithCallback` prepends the right prefix and emits **no** trailing
   newline (the sink adds it — `Printfln` for stdout).

Then run `go build ./...`, `go vet ./...`, `gofmt -l`, and `go test ./...`.
