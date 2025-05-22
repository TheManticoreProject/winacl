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
func (dacl *DiscretionaryAccessControlList) Unmarshal(marshalledData []byte) (int, error) {
	dacl.RawBytesSize = 0
	dacl.RawBytes = marshalledData

	rawBytesSize, err := dacl.Header.Unmarshal(marshalledData)
	if err != nil {
		return 0, err
	}
	dacl.RawBytesSize += uint32(rawBytesSize)
	marshalledData = marshalledData[dacl.RawBytesSize:]

	// Parse all ACEs
	for index := 0; index < int(dacl.Header.AceCount); index++ {
		entry := ace.AccessControlEntry{}
		rawBytesSize, err := entry.Unmarshal(marshalledData)
		if err != nil {
			return 0, err
		}
		entry.Index = uint16(index + 1)
		dacl.Entries = append(dacl.Entries, entry)
		dacl.RawBytesSize += uint32(rawBytesSize)
		marshalledData = marshalledData[rawBytesSize:]
	}

	dacl.RawBytes = dacl.RawBytes[:dacl.RawBytesSize]

	return int(dacl.RawBytesSize), nil
}

// Marshal serializes the DiscretionaryAccessControlList struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the DACL.
func (dacl *DiscretionaryAccessControlList) Marshal() ([]byte, error) {
	var serializedData []byte

	bytesStream, err := dacl.Header.Marshal()
	if err != nil {
		return nil, err
	}
	serializedData = append(serializedData, bytesStream...)

	for _, ace := range dacl.Entries {
		bytesStream, err := ace.Marshal()
		if err != nil {
			return nil, err
		}
		serializedData = append(serializedData, bytesStream...)
	}

	return serializedData, nil
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
