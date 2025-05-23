package acl

import (
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

// Unmarshal parses the raw byte slice and initializes the SystemAccessControlList struct.
// It sets the RawBytes and RawBytesSize fields, parses the header, and then parses each ACE.
//
// Parameters:
//   - rawBytes ([]byte): The raw byte slice to be parsed.
func (sacl *SystemAccessControlList) Unmarshal(marshalledData []byte) (int, error) {
	sacl.RawBytesSize = 0
	sacl.RawBytes = marshalledData

	// Unmarshal the header
	rawBytesSize, err := sacl.Header.Unmarshal(marshalledData)
	if err != nil {
		return 0, err
	}
	sacl.RawBytesSize += uint32(rawBytesSize)
	marshalledData = marshalledData[rawBytesSize:]

	// Unmarshal all ACEs
	for index := 0; index < int(sacl.Header.AceCount); index++ {
		entry := ace.AccessControlEntry{}
		rawBytesSize, err := entry.Unmarshal(marshalledData)
		if err != nil {
			return 0, err
		}
		entry.Index = uint16(index + 1)
		sacl.Entries = append(sacl.Entries, entry)
		sacl.RawBytesSize += uint32(rawBytesSize)
		marshalledData = marshalledData[rawBytesSize:]
	}

	sacl.RawBytes = sacl.RawBytes[:sacl.RawBytesSize]

	return int(sacl.RawBytesSize), nil
}

// Marshal serializes the SystemAccessControlList struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the SACL.
func (sacl *SystemAccessControlList) Marshal() ([]byte, error) {
	var serializedData []byte

	// Marshal the header
	bytesStream, err := sacl.Header.Marshal()
	if err != nil {
		return nil, err
	}
	serializedData = append(serializedData, bytesStream...)

	// Marshal the entries
	for _, ace := range sacl.Entries {
		bytesStream, err := ace.Marshal()
		if err != nil {
			return nil, err
		}
		serializedData = append(serializedData, bytesStream...)
	}

	return serializedData, nil
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
