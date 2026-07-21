package acl

import (
	"encoding/binary"
	"fmt"

	"github.com/TheManticoreProject/winacl/acl/revision"
	"github.com/TheManticoreProject/winacl/utils/describe"
)

// DiscretionaryAccessControlListHeader represents the header of a Discretionary Access Control List (DACL).
type DiscretionaryAccessControlListHeader struct {
	Revision revision.AccessControlListRevision
	Sbz1     uint8
	AclSize  uint16
	AceCount uint16
	Sbz2     uint16

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Unmarshal initializes the DiscretionaryAccessControlListHeader struct by parsing the raw byte slice.
// It sets the RawBytes and RawBytesSize fields, parses the header, and then parses each ACE.
//
// Parameters:
//   - rawBytes ([]byte): The raw byte slice to be parsed.
//
// Returns:
//   - error: An error if parsing fails, otherwise nil.
func (daclheader *DiscretionaryAccessControlListHeader) Unmarshal(marshalledData []byte) (int, error) {
	// Parsing header
	if len(marshalledData) < 8 {
		return 0, fmt.Errorf("invalid raw bytes length")
	}

	daclheader.RawBytes = marshalledData[:8]
	daclheader.RawBytesSize = 0

	rawBytesSize, err := daclheader.Revision.Unmarshal(marshalledData[:1])
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal Revision: %w", err)
	}
	daclheader.RawBytesSize += uint32(rawBytesSize)

	daclheader.Sbz1 = marshalledData[1]
	daclheader.RawBytesSize += 1

	daclheader.AclSize = binary.LittleEndian.Uint16(marshalledData[2:4])
	daclheader.RawBytesSize += 2

	daclheader.AceCount = binary.LittleEndian.Uint16(marshalledData[4:6])
	daclheader.RawBytesSize += 2

	daclheader.Sbz2 = binary.LittleEndian.Uint16(marshalledData[6:8])
	daclheader.RawBytesSize += 2

	return int(daclheader.RawBytesSize), nil
}

// Marshal serializes the DiscretionaryAccessControlListHeader struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the DACL header.
func (daclheader *DiscretionaryAccessControlListHeader) Marshal() ([]byte, error) {
	var marshalledData []byte

	daclheader.RawBytesSize = 0

	bytesStream, err := daclheader.Revision.Marshal()
	if err != nil {
		return nil, err
	}
	marshalledData = append(marshalledData, bytesStream...)
	daclheader.RawBytesSize += uint32(len(bytesStream))

	marshalledData = append(marshalledData, daclheader.Sbz1)
	daclheader.RawBytesSize += 1

	buffer := make([]byte, 2)
	binary.LittleEndian.PutUint16(buffer, daclheader.AclSize)
	marshalledData = append(marshalledData, buffer...)
	daclheader.RawBytesSize += 2

	binary.LittleEndian.PutUint16(buffer, daclheader.AceCount)
	marshalledData = append(marshalledData, buffer...)
	daclheader.RawBytesSize += 2

	binary.LittleEndian.PutUint16(buffer, daclheader.Sbz2)
	marshalledData = append(marshalledData, buffer...)
	daclheader.RawBytesSize += 2

	daclheader.RawBytes = marshalledData

	return marshalledData, nil
}

// DescribeList returns the DiscretionaryAccessControlListHeader description as a
// list of lines at indentation depth 0.
func (daclheader *DiscretionaryAccessControlListHeader) DescribeList() []string {
	return []string{
		"<DiscretionaryAccessControlListHeader>",
		fmt.Sprintf(" │ \x1b[93mRevision\x1b[0m : \x1b[96m0x%02x\x1b[0m (\x1b[94m%s\x1b[0m)", daclheader.Revision.Value, daclheader.Revision.String()),
		fmt.Sprintf(" │ \x1b[93mSbz1\x1b[0m     : \x1b[96m0x%02x\x1b[0m", daclheader.Sbz1),
		fmt.Sprintf(" │ \x1b[93mAclSize\x1b[0m  : \x1b[96m0x%04x\x1b[0m", daclheader.AclSize),
		fmt.Sprintf(" │ \x1b[93mAceCount\x1b[0m : \x1b[96m0x%04x (%d)\x1b[0m", daclheader.AceCount, daclheader.AceCount),
		fmt.Sprintf(" │ \x1b[93mSbz2\x1b[0m     : \x1b[96m0x%04x\x1b[0m", daclheader.Sbz2),
		" └─",
	}
}

// DescribeWithCallback renders the DiscretionaryAccessControlListHeader at the
// given indentation depth, routing each line to the provided fmt.Printf-like
// callback.
func (daclheader *DiscretionaryAccessControlListHeader) DescribeWithCallback(indent int, printf describe.Printf) {
	describe.WithCallback(indent, daclheader.DescribeList(), printf)
}

func (daclheader *DiscretionaryAccessControlListHeader) Describe(indent int) {
	daclheader.DescribeWithCallback(indent, describe.Printfln)
}
