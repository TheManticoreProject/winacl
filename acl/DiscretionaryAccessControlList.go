package acl

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/winacl/ace"
)

// DiscretionaryAccessControlList represents a Discretionary Access Control List (DACL).
type DiscretionaryAccessControlList struct {
	Header  DiscretionaryAccessControlListHeader
	Entries []ace.AccessControlEntry
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Parse initializes the DiscretionaryAccessControlList struct by parsing the raw byte slice.
// It sets the RawBytes and RawBytesSize fields, parses the header, and then parses each ACE.
//
// Parameters:
//   - rawBytes ([]byte): The raw byte slice to be parsed.
func (dacl *DiscretionaryAccessControlList) Parse(rawBytes []byte) {
	dacl.RawBytesSize = 0
	dacl.RawBytes = rawBytes

	dacl.Header.Parse(rawBytes)
	dacl.RawBytesSize += dacl.Header.RawBytesSize
	rawBytes = rawBytes[dacl.RawBytesSize:]

	// Parse all ACEs
	for index := 0; index < int(dacl.Header.AceCount); index++ {
		entry := ace.AccessControlEntry{}
		entry.Parse(rawBytes)
		entry.Index = uint16(index + 1)
		dacl.Entries = append(dacl.Entries, entry)
		dacl.RawBytesSize += entry.RawBytesSize
		rawBytes = rawBytes[entry.RawBytesSize:]
	}

	dacl.RawBytes = dacl.RawBytes[:dacl.RawBytesSize]
}

// ToBytes serializes the DiscretionaryAccessControlList struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the DACL.
func (dacl *DiscretionaryAccessControlList) ToBytes() []byte {
	var serializedData []byte

	serializedData = append(serializedData, dacl.Header.ToBytes()...)

	for _, ace := range dacl.Entries {
		serializedData = append(serializedData, ace.ToBytes()...)
	}

	return serializedData
}

// Describe prints a detailed description of the DiscretionaryAccessControlList struct,
// including its attributes formatted with indentation for clarity.
//
// Parameters:
//   - indent (int): The indentation level for formatting the output. Each level increases
//     the indentation depth, allowing for a hierarchical display of the DACL's components.
func (dacl *DiscretionaryAccessControlList) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<DiscretionaryAccessControlList>\n", indentPrompt)

	dacl.Header.Describe(indent + 1)

	for _, ace := range dacl.Entries {
		ace.Describe(indent + 1)
	}

	fmt.Printf("%s └─\n", indentPrompt)
}
