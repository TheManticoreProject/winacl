package acl

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// SystemAccessControlListHeader represents the header of a System Access Control List (SACL).
type SystemAccessControlListHeader struct {
	Revision AccessControlListRevision
	Sbz1     uint8
	AclSize  uint16
	AceCount uint16
	Sbz2     uint16
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Parse initializes the SystemAccessControlListHeader struct by parsing the raw byte slice.
// It sets the RawBytes and RawBytesSize fields, parses the header, and then parses each ACE.
//
// Parameters:
//   - rawBytes ([]byte): The raw byte slice to be parsed.
//
// Returns:
//   - error: An error if parsing fails, otherwise nil.
func (saclheader *SystemAccessControlListHeader) Unmarshal(marshalledData []byte) (int, error) {
	// Parsing header
	if len(marshalledData) < 8 {
		return 0, fmt.Errorf("invalid raw bytes length")
	}

	saclheader.RawBytes = marshalledData[:8]
	saclheader.RawBytesSize = 0

	rawBytesSize, err := saclheader.Revision.Unmarshal(marshalledData[:1])
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal Revision: %w", err)
	}
	saclheader.RawBytesSize += uint32(rawBytesSize)

	saclheader.Sbz1 = marshalledData[1]
	saclheader.RawBytesSize += 1

	saclheader.AclSize = binary.LittleEndian.Uint16(marshalledData[2:4])
	saclheader.RawBytesSize += 2

	saclheader.AceCount = binary.LittleEndian.Uint16(marshalledData[4:6])
	saclheader.RawBytesSize += 2

	saclheader.Sbz2 = binary.LittleEndian.Uint16(marshalledData[6:8])
	saclheader.RawBytesSize += 2

	return int(saclheader.RawBytesSize), nil
}

// Marshal serializes the SystemAccessControlListHeader struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the SACL header.
func (saclheader *SystemAccessControlListHeader) Marshal() ([]byte, error) {
	var marshalledData []byte

	bytesStream, err := saclheader.Revision.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Revision: %w", err)
	}
	marshalledData = append(marshalledData, bytesStream...)
	saclheader.RawBytesSize += uint32(len(bytesStream))

	marshalledData = append(marshalledData, saclheader.Sbz1)
	saclheader.RawBytesSize += 1

	buffer := make([]byte, 2)
	binary.LittleEndian.PutUint16(buffer, saclheader.AclSize)
	marshalledData = append(marshalledData, buffer...)
	saclheader.RawBytesSize += 2

	binary.LittleEndian.PutUint16(buffer, saclheader.AceCount)
	marshalledData = append(marshalledData, buffer...)
	saclheader.RawBytesSize += 2

	binary.LittleEndian.PutUint16(buffer, saclheader.Sbz2)
	marshalledData = append(marshalledData, buffer...)
	saclheader.RawBytesSize += 2

	return marshalledData, nil
}

// Describe prints a detailed description of the SystemAccessControlListHeader struct,
// including its attributes formatted with indentation for clarity.
//
// Parameters:
//   - indent (int): The indentation level for formatting the output. Each level increases
//     the indentation depth, allowing for a hierarchical display of the SACL's components.
func (saclheader *SystemAccessControlListHeader) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<SystemAccessControlListHeader>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mRevision\x1b[0m : \x1b[96m0x%02x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, saclheader.Revision.Value, saclheader.Revision.String())
	fmt.Printf("%s │ \x1b[93mSbz1\x1b[0m     : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, saclheader.Sbz1)
	fmt.Printf("%s │ \x1b[93mAclSize\x1b[0m  : \x1b[96m0x%04x\x1b[0m\n", indentPrompt, saclheader.AclSize)
	fmt.Printf("%s │ \x1b[93mAceCount\x1b[0m : \x1b[96m0x%04x\x1b[0m (%d)\x1b[0m\n", indentPrompt, saclheader.AceCount, saclheader.AceCount)
	fmt.Printf("%s │ \x1b[93mSbz2\x1b[0m     : \x1b[96m0x%04x\x1b[0m\n", indentPrompt, saclheader.Sbz2)
	fmt.Printf("%s └─\n", indentPrompt)
}
