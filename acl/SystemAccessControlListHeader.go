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
func (saclheader *SystemAccessControlListHeader) Parse(rawBytes []byte) error {
	// Parsing header
	if len(rawBytes) < 8 {
		return fmt.Errorf("invalid raw bytes length")
	}

	saclheader.RawBytes = rawBytes[:8]
	saclheader.RawBytesSize = 8

	saclheader.Revision.Parse(rawBytes[:1])

	saclheader.Sbz1 = rawBytes[1]

	saclheader.AclSize = binary.LittleEndian.Uint16(rawBytes[2:4])

	saclheader.AceCount = binary.LittleEndian.Uint16(rawBytes[4:6])

	saclheader.Sbz2 = binary.LittleEndian.Uint16(rawBytes[6:8])

	return nil
}

// ToBytes serializes the SystemAccessControlListHeader struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the SACL header.
func (saclheader *SystemAccessControlListHeader) ToBytes() []byte {
	var serializedData []byte

	serializedData = append(serializedData, saclheader.Revision.ToBytes()...)

	serializedData = append(serializedData, saclheader.Sbz1)

	buffer := make([]byte, 2)
	binary.LittleEndian.PutUint16(buffer, saclheader.AclSize)
	serializedData = append(serializedData, buffer...)

	binary.LittleEndian.PutUint16(buffer, saclheader.AceCount)
	serializedData = append(serializedData, buffer...)

	binary.LittleEndian.PutUint16(buffer, saclheader.Sbz2)
	serializedData = append(serializedData, buffer...)

	return serializedData
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
