package sddl

import (
	"strings"
)

// CutSDDL parses an SDDL string into its component parts.
//
// Parameters:
//   - sddlString (string): The SDDL string to parse.
//
// Returns:
//   - (string, string, []string, []string): The owner SID, group SID, DACL ACEs, and SACL ACEs.
func CutSDDL(sddlString string) (string, string, []string, []string) {
	sddlString = strings.TrimSpace(sddlString)

	// Match components starting with O:, G:, D:, or S: using regex
	components := map[string]string{
		"O:": "",
		"G:": "",
		"D:": "",
		"S:": "",
	}

	currentComponent := ""
	k := 0
	for {
		upperChar := strings.ToUpper(string(sddlString[k]))
		if (upperChar == "O" || upperChar == "G" || upperChar == "D" || upperChar == "S") && (sddlString[k+1] == ':') {
			currentComponent = sddlString[k : k+2]
			k += 1
		} else {
			components[currentComponent] += string(sddlString[k])
		}

		k++
		if k >= len(sddlString) {
			break
		}
	}

	daclAces := CutAces(components["D:"])
	saclAces := CutAces(components["S:"])

	return components["O:"], components["G:"], daclAces, saclAces
}

// CutAces extracts individual ACE strings from a DACL/SACL component.
// Handles the format: flags(ace1)(ace2)...(aceN)
func CutAces(aclStr string) []string {
	var aces []string

	// Find first ( to separate flags
	start := strings.Index(aclStr, "(")
	if start == -1 {
		return aces
	}

	// Extract ACEs between parentheses
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
			if depth == 0 {
				aces = append(aces, aclStr[aceStart:i])
			}
		}
	}

	return aces
}
