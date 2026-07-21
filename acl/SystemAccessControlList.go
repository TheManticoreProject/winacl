package acl

import (
	"fmt"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/utils/describe"
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
	totalSize := 8 + len(marshalledData)
	if totalSize > 0xFFFF {
		return nil, fmt.Errorf("SACL too large to marshal: size %d exceeds the uint16 AclSize maximum (65535)", totalSize)
	}
	sacl.Header.AclSize = uint16(totalSize)
	bytesStream, err := sacl.Header.Marshal()
	if err != nil {
		return nil, err
	}
	marshalledData = append(bytesStream, marshalledData...)

	return marshalledData, nil
}

// DescribeList returns the SystemAccessControlList description as a list of
// lines at indentation depth 0, nesting the header and each entry one level
// deeper.
func (sacl *SystemAccessControlList) DescribeList() []string {
	lines := []string{"<SystemAccessControlList>"}

	lines = append(lines, describe.Nest(sacl.Header.DescribeList())...)

	for _, ace := range sacl.Entries {
		lines = append(lines, describe.Nest(ace.DescribeList())...)
	}

	lines = append(lines, " └─")

	return lines
}

// DescribeWithCallback renders the SystemAccessControlList at the given
// indentation depth, routing each line to the provided fmt.Printf-like callback.
func (sacl *SystemAccessControlList) DescribeWithCallback(indent int, printf describe.Printf) {
	describe.WithCallback(indent, sacl.DescribeList(), printf)
}

func (sacl *SystemAccessControlList) Describe(indent int) {
	sacl.DescribeWithCallback(indent, fmt.Printf)
}
