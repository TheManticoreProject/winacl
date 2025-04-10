package acl

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/winacl/ace"
)

// SystemAccessControlList represents a System Access Control List (SACL).
type SystemAccessControlList struct {
	Header  SystemAccessControlListHeader
	Entries []ace.AccessControlEntry
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Parse initializes the SystemAccessControlList struct by parsing the raw byte slice.
// It sets the RawBytes and RawBytesSize fields, parses the header, and then parses each ACE.
//
// Parameters:
//   - rawBytes ([]byte): The raw byte slice to be parsed.
func (sacl *SystemAccessControlList) Parse(rawBytes []byte) {
	debug := false

	sacl.RawBytesSize = 0
	sacl.RawBytes = rawBytes

	if debug {
		fmt.Printf("[debug][SystemAccessControlList.Parse()] rawBytes: %s\n", hex.EncodeToString(rawBytes))
	}
	sacl.Header.Parse(rawBytes)
	sacl.RawBytesSize += sacl.Header.RawBytesSize
	rawBytes = rawBytes[sacl.RawBytesSize:]

	// Parse all ACEs
	for index := 0; index < int(sacl.Header.AceCount); index++ {
		if debug {
			fmt.Printf("[debug][SystemAccessControlList.Parse()] Parsing ACE %d/%d: %s\n", index+1, int(sacl.Header.AceCount), hex.EncodeToString(rawBytes))
		}
		entry := ace.AccessControlEntry{}
		entry.Parse(rawBytes)
		entry.Index = uint16(index + 1)
		sacl.Entries = append(sacl.Entries, entry)
		sacl.RawBytesSize += entry.RawBytesSize
		rawBytes = rawBytes[entry.RawBytesSize:]
	}

	sacl.RawBytes = sacl.RawBytes[:sacl.RawBytesSize]
}

// ToBytes serializes the SystemAccessControlList struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the SACL.
func (sacl *SystemAccessControlList) ToBytes() []byte {
	var serializedData []byte

	serializedData = append(serializedData, sacl.Header.ToBytes()...)

	for _, ace := range sacl.Entries {
		serializedData = append(serializedData, ace.ToBytes()...)
	}

	return serializedData
}

// Describe prints a detailed description of the SystemAccessControlList struct,
// including its attributes formatted with indentation for clarity.
//
// Parameters:
//   - indent (int): The indentation level for formatting the output. Each level increases
//     the indentation depth, allowing for a hierarchical display of the SACL's components.
func (sacl *SystemAccessControlList) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<SystemAccessControlList>\n", indentPrompt)

	sacl.Header.Describe(indent + 1)

	for _, ace := range sacl.Entries {
		ace.Describe(indent + 1)
	}

	fmt.Printf("%s └─\n", indentPrompt)
}
