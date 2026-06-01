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

	// Bound ACE parsing to the region declared by AclSize. The caller hands in
	// the entire remaining buffer (in a security descriptor the ACL is followed
	// by the Owner/Group SIDs), so without this bound a corrupt or oversized
	// AceCount would walk past the ACL and mis-parse adjacent components as ACEs.
	if int(sacl.Header.AclSize) < rawBytesSize {
		return 0, fmt.Errorf("invalid SACL: AclSize (%d) is smaller than the header size (%d)", sacl.Header.AclSize, rawBytesSize)
	}
	aceRegionLen := int(sacl.Header.AclSize) - rawBytesSize
	if aceRegionLen > len(marshalledData) {
		return 0, fmt.Errorf("invalid SACL: AclSize (%d) exceeds available data (%d)", sacl.Header.AclSize, rawBytesSize+len(marshalledData))
	}
	aceData := marshalledData[:aceRegionLen]

	// Unmarshal all ACEs
	for index := 0; index < int(sacl.Header.AceCount); index++ {
		entry := ace.AccessControlEntry{}
		rawBytesSize, err := entry.Unmarshal(aceData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal ACE %d/%d within AclSize: %w", index+1, sacl.Header.AceCount, err)
		}
		entry.Index = uint16(index + 1)
		sacl.Entries = append(sacl.Entries, entry)
		sacl.RawBytesSize += uint32(rawBytesSize)
		aceData = aceData[rawBytesSize:]
	}

	sacl.RawBytes = sacl.RawBytes[:sacl.RawBytesSize]

	return int(sacl.RawBytesSize), nil
}

// Marshal serializes the SystemAccessControlList struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the SACL.
func (sacl *SystemAccessControlList) Marshal() ([]byte, error) {
	var marshalledData []byte

	// Marshal the entries
	for _, ace := range sacl.Entries {
		bytesStream, err := ace.Marshal()
		if err != nil {
			return nil, err
		}
		marshalledData = append(marshalledData, bytesStream...)
	}

	// Marshal the header at the beginning of the serialized data
	// We need to include the header in the size calculation, it is 8 bytes long
	sacl.Header.AclSize = uint16(8 + len(marshalledData))
	bytesStream, err := sacl.Header.Marshal()
	if err != nil {
		return nil, err
	}
	marshalledData = append(bytesStream, marshalledData...)

	return marshalledData, nil
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
