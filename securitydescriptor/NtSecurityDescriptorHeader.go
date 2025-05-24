package securitydescriptor

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// NtSecurityDescriptorHeader represents the header of a NT Security Descriptor,
// which contains information about the security attributes of an object.
//
// Attributes:
//   - Revision (uint8): The revision level of the security descriptor.
//   - Sbz1 (uint8): Reserved byte, must be zero.
//   - Control (uint16): Control flags that define the security descriptor's behavior.
//   - OffsetOwner (uint32): Offset (in bytes) to the owner SID in the security descriptor.
//   - OffsetGroup (uint32): Offset (in bytes) to the group SID in the security descriptor.
//   - OffsetSacl (uint32): Offset (in bytes) to the System Access Control List (SACL).
//   - OffsetDacl (uint32): Offset (in bytes) to the Discretionary Access Control List (DACL).
//
// Internal attributes:
//   - RawBytes ([]byte): The raw byte data representing the security descriptor header.
//   - RawBytesSize (uint32): The size of the raw byte data.
type NtSecurityDescriptorHeader struct {
	Revision    uint8
	Sbz1        uint8
	Control     NtSecurityDescriptorControl
	OffsetOwner uint32
	OffsetGroup uint32
	OffsetSacl  uint32
	OffsetDacl  uint32

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Unmarshal populates the NtSecurityDescriptorHeader struct by parsing the provided raw byte slice.
// It extracts the header information and validates the length of the raw bytes.
//
// Parameters:
//   - RawBytes ([]byte): The raw byte data containing the security descriptor header information.
//
// Returns:
//   - error: Returns an error if the raw bytes length is insufficient or if parsing fails.
func (ntsd *NtSecurityDescriptorHeader) Unmarshal(marshalledData []byte) (int, error) {
	// Parsing header
	if len(marshalledData) < 20 {
		return 0, fmt.Errorf("invalid raw bytes length")
	}

	ntsd.RawBytes = marshalledData[:20]
	ntsd.RawBytesSize = 0

	ntsd.Revision = marshalledData[0]
	ntsd.RawBytesSize += 1

	ntsd.Sbz1 = marshalledData[1]
	ntsd.RawBytesSize += 1

	ntsd.Control = NtSecurityDescriptorControl{}
	bytesRead, err := ntsd.Control.Unmarshal(marshalledData[2:4])
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal Control: %w", err)
	}
	ntsd.RawBytesSize += uint32(bytesRead)

	ntsd.OffsetOwner = binary.LittleEndian.Uint32(marshalledData[4:8])
	ntsd.RawBytesSize += 4

	ntsd.OffsetGroup = binary.LittleEndian.Uint32(marshalledData[8:12])
	ntsd.RawBytesSize += 4

	ntsd.OffsetSacl = binary.LittleEndian.Uint32(marshalledData[12:16])
	ntsd.RawBytesSize += 4

	ntsd.OffsetDacl = binary.LittleEndian.Uint32(marshalledData[16:20])
	ntsd.RawBytesSize += 4

	return 20, nil
}

// Marshal serializes the NtSecurityDescriptorHeader struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the security descriptor header.
func (ntsdh *NtSecurityDescriptorHeader) Marshal() ([]byte, error) {
	serializedData := []byte{}

	serializedData = append(serializedData, ntsdh.Revision)

	serializedData = append(serializedData, ntsdh.Sbz1)

	bytesStream, err := ntsdh.Control.Marshal()
	if err != nil {
		return nil, err
	}
	serializedData = append(serializedData, bytesStream...)

	buffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(buffer, ntsdh.OffsetOwner)
	serializedData = append(serializedData, buffer...)

	binary.LittleEndian.PutUint32(buffer, ntsdh.OffsetGroup)
	serializedData = append(serializedData, buffer...)

	binary.LittleEndian.PutUint32(buffer, ntsdh.OffsetSacl)
	serializedData = append(serializedData, buffer...)

	binary.LittleEndian.PutUint32(buffer, ntsdh.OffsetDacl)
	serializedData = append(serializedData, buffer...)

	return serializedData, nil
}

// Describe prints a detailed description of the NtSecurityDescriptorHeader struct,
// including its attributes formatted with indentation for clarity.
//
// Parameters:
//   - indent (int): The indentation level for formatting the output. Each level increases
//     the indentation depth, allowing for a hierarchical display of the header's components.
func (ntsd *NtSecurityDescriptorHeader) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<NtSecurityDescriptorHeader>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mRevision\x1b[0m    : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, ntsd.Revision)
	fmt.Printf("%s │ \x1b[93mSbz1\x1b[0m        : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, ntsd.Sbz1)
	fmt.Printf("%s │ \x1b[93mControl\x1b[0m     : \x1b[96m0x%04x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, ntsd.Control.RawValue, strings.Join(ntsd.Control.Flags, "|"))
	fmt.Printf("%s │ \x1b[93mOffsetOwner\x1b[0m : \x1b[96m0x%08x\x1b[0m\n", indentPrompt, ntsd.OffsetOwner)
	fmt.Printf("%s │ \x1b[93mOffsetGroup\x1b[0m : \x1b[96m0x%08x\x1b[0m\n", indentPrompt, ntsd.OffsetGroup)
	fmt.Printf("%s │ \x1b[93mOffsetSacl\x1b[0m  : \x1b[96m0x%08x\x1b[0m\n", indentPrompt, ntsd.OffsetSacl)
	fmt.Printf("%s │ \x1b[93mOffsetDacl\x1b[0m  : \x1b[96m0x%08x\x1b[0m\n", indentPrompt, ntsd.OffsetDacl)
	fmt.Printf("%s └─\n", indentPrompt)
}
