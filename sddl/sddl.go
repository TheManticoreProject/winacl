package sddl

import (
	"fmt"
	"strings"
)

// CutSDDL parses an SDDL string into its component parts.
//
// The scan is parenthesis-aware: the O:, G:, D:, and S: component markers are
// only recognised at the top level (parenthesis depth 0), so a ':' or a marker
// letter appearing inside an ACE body (for example in a conditional or
// resource-attribute ACE) does not split the string. Malformed input — leading
// characters before the first marker, or unbalanced parentheses — is reported
// as an error instead of being silently discarded.
//
// Parameters:
//   - sddlString (string): The SDDL string to parse.
//
// Returns:
//   - (string, string, []string, []string, error): The owner SID, group SID,
//     DACL ACEs, SACL ACEs, and an error if the string is malformed.
func CutSDDL(sddlString string) (string, string, []string, []string, error) {
	sddlString = strings.TrimSpace(sddlString)

	if len(sddlString) == 0 {
		return "", "", nil, nil, nil
	}

	// Match components starting with O:, G:, D:, or S:.
	components := map[string]string{
		"O:": "",
		"G:": "",
		"D:": "",
		"S:": "",
	}

	currentComponent := ""
	depth := 0
	k := 0
	for k < len(sddlString) {
		c := sddlString[k]

		// A component marker can only start at the top level. Recognising markers
		// at depth > 0 would let an ACE body containing "D:" (etc.) be mistaken
		// for a new component.
		if depth == 0 && k+1 < len(sddlString) && sddlString[k+1] == ':' {
			upperChar := strings.ToUpper(string(c))
			if upperChar == "O" || upperChar == "G" || upperChar == "D" || upperChar == "S" {
				// Normalise the key to uppercase so lowercase markers (o:, g:, d:,
				// s:) land in the same bucket as their uppercase counterparts; SDDL
				// is case-insensitive at the component-marker level.
				currentComponent = upperChar + ":"
				k += 2
				continue
			}
		}

		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return "", "", nil, nil, fmt.Errorf("malformed SDDL: unbalanced ')' at position %d", k)
			}
		}

		if currentComponent == "" {
			// Any character before the first component marker is invalid; the
			// string has already been trimmed, so this is genuine garbage.
			return "", "", nil, nil, fmt.Errorf("malformed SDDL: unexpected character %q at position %d before any component marker", c, k)
		}
		components[currentComponent] += string(c)
		k++
	}

	if depth != 0 {
		return "", "", nil, nil, fmt.Errorf("malformed SDDL: unbalanced '(' (missing %d closing parenthesis)", depth)
	}

	daclAces, err := CutAces(components["D:"])
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("invalid DACL: %w", err)
	}
	saclAces, err := CutAces(components["S:"])
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("invalid SACL: %w", err)
	}

	return components["O:"], components["G:"], daclAces, saclAces, nil
}

// CutAces extracts individual ACE strings from a DACL/SACL component.
// Handles the format: flags(ace1)(ace2)...(aceN)
//
// Nested parentheses inside an ACE (for example in a conditional expression)
// are preserved: only top-level parentheses delimit ACEs. Unbalanced
// parentheses and stray characters between or after ACEs are reported as an
// error rather than silently dropping or truncating ACEs.
func CutAces(aclStr string) ([]string, error) {
	var aces []string

	// Find first ( to separate flags. No '(' means the component has no ACEs
	// (e.g. an empty DACL with only flags), which is valid.
	start := strings.Index(aclStr, "(")
	if start == -1 {
		return aces, nil
	}

	// Extract ACEs between top-level parentheses.
	depth := 0
	aceStart := start
	for i := start; i < len(aclStr); i++ {
		switch aclStr[i] {
		case '(':
			if depth == 0 {
				aceStart = i + 1
			}
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced ')' at position %d", i)
			}
			if depth == 0 {
				aces = append(aces, aclStr[aceStart:i])
			}
		default:
			if depth == 0 {
				return nil, fmt.Errorf("unexpected character %q at position %d (outside any ACE)", aclStr[i], i)
			}
		}
	}

	if depth != 0 {
		return nil, fmt.Errorf("unbalanced '(' (missing %d closing parenthesis)", depth)
	}

	return aces, nil
}
