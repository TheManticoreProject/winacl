package utils

import "strings"

// MultiSplit splits a string on multiple delimiters.
// It takes a string and a slice of delimiters, and returns a slice of strings split on any of the delimiters.
//
// Parameters:
//   - s (string): The string to split
//   - delims []string: Slice of delimiter strings to split on
//
// Returns:
//   - []string: Slice containing the split string parts
func MultiSplit(s string, delims []string) []string {
	if len(delims) == 0 {
		return []string{s}
	}

	// Start with first delimiter
	result := []string{}
	parts := []string{s}

	// Split on each delimiter in sequence
	for _, delim := range delims {
		newParts := []string{}
		for _, p := range parts {
			splitParts := strings.Split(p, delim)
			newParts = append(newParts, splitParts...)
		}
		parts = newParts
	}

	// Remove empty strings and add non-empty parts to result
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}

	return result
}
