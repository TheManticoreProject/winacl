package securitydescriptor

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/winacl/acl"
	"github.com/TheManticoreProject/winacl/identity"
)

// NtSecurityDescriptor represents a Windows security descriptor.
type NtSecurityDescriptor struct {
	Header NtSecurityDescriptorHeader

	Owner identity.Identity
	Group identity.Identity

	DACL acl.DiscretionaryAccessControlList
	SACL acl.SystemAccessControlList

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Unmarshal initializes the NtSecurityDescriptor struct by parsing the raw byte array.
//
// Parameters:
//   - rawBytes ([]byte): The raw byte array to be parsed.
//
// Returns:
//   - error: An error if parsing fails, otherwise nil.
func (ntsd *NtSecurityDescriptor) Unmarshal(marshalledData []byte) (int, error) {
	ntsd.RawBytes = marshalledData
	ntsd.RawBytesSize = 0

	// Unmarshal the header
	rawBytesSize, err := ntsd.Header.Unmarshal(marshalledData)
	if err != nil {
		return 0, err
	}
	ntsd.RawBytesSize += uint32(rawBytesSize)

	// Unmarshal Owner if present
	if ntsd.Header.OffsetOwner != 0 {
		rawBytesSize, err := ntsd.Owner.Unmarshal(ntsd.RawBytes[ntsd.Header.OffsetOwner:])
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Owner: %w", err)
		}
		ntsd.RawBytesSize += uint32(rawBytesSize)
	}

	// Unmarshal Group if present
	if ntsd.Header.OffsetGroup != 0 {
		rawBytesSize, err := ntsd.Group.Unmarshal(ntsd.RawBytes[ntsd.Header.OffsetGroup:])
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Group: %w", err)
		}
		ntsd.RawBytesSize += uint32(rawBytesSize)
	}

	// Unmarshal DACL if present
	if ntsd.Header.OffsetDacl != 0 {
		rawBytesSize, err := ntsd.DACL.Unmarshal(ntsd.RawBytes[ntsd.Header.OffsetDacl:])
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal DACL: %w", err)
		}
		ntsd.RawBytesSize += uint32(rawBytesSize)
	}

	// Unmarshal SACL if present
	if ntsd.Header.OffsetSacl != 0 {
		rawBytesSize, err := ntsd.SACL.Unmarshal(ntsd.RawBytes[ntsd.Header.OffsetSacl:])
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal SACL: %w", err)
		}
		ntsd.RawBytesSize += uint32(rawBytesSize)
	}

	return int(ntsd.RawBytesSize), nil
}

// Marshal serializes the NtSecurityDescriptor struct into a byte slice.
//
// Returns:
//   - ([]byte, error): A byte slice containing the serialized data and an error if serialization fails, otherwise nil.
func (ntsd *NtSecurityDescriptor) Marshal() ([]byte, error) {
	// Initialize a byte slice to hold the serialized data
	var err error
	var marshaledData []byte

	// Marshal SACL
	dataSacl := []byte{}
	offsetSacl := 0
	if len(ntsd.SACL.Entries) > 0 {
		dataSacl, err = ntsd.SACL.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal SACL: %w", err)
		}
		offsetSacl = 20 // (0x00000014)
	}

	// Marshal DACL
	dataDacl := []byte{}
	offsetDacl := 0
	if len(ntsd.DACL.Entries) > 0 {
		dataDacl, err = ntsd.DACL.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal DACL: %w", err)
		}
		offsetDacl = offsetSacl + len(dataSacl)
	}

	// Marshal Owner
	dataOwner, err := ntsd.Owner.SID.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Owner: %w", err)
	}
	offsetOwner := offsetSacl + len(dataSacl) + len(dataDacl)

	// Marshal Group
	dataGroup, err := ntsd.Group.SID.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Group: %w", err)
	}
	offsetGroup := offsetSacl + len(dataSacl) + len(dataDacl) + len(dataOwner)

	// Update the header and append the header bytes
	ntsd.Header.OffsetOwner = uint32(offsetOwner)
	ntsd.Header.OffsetGroup = uint32(offsetGroup)
	ntsd.Header.OffsetSacl = uint32(offsetSacl)
	ntsd.Header.OffsetDacl = uint32(offsetDacl)
	marshaledData, err = ntsd.Header.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Header: %w", err)
	}

	// Append the SACL bytes if present
	if ntsd.Header.OffsetSacl != 0 {
		marshaledData = append(marshaledData, dataSacl...)
	}
	// Append the DACL bytes if present
	if ntsd.Header.OffsetDacl != 0 {
		marshaledData = append(marshaledData, dataDacl...)
	}
	// Append the Owner SID bytes if present
	if ntsd.Header.OffsetOwner != 0 {
		marshaledData = append(marshaledData, dataOwner...)
	}
	// Append the Group SID bytes if present
	if ntsd.Header.OffsetGroup != 0 {
		marshaledData = append(marshaledData, dataGroup...)
	}

	return marshaledData, nil
}

// Describe prints the NtSecurityDescriptor in a human-readable format.
//
// Parameters:
//   - indent (int): The indentation level for the output.
func (ntsd *NtSecurityDescriptor) Describe(indent int) {
	fmt.Println("<NTSecurityDescriptor>")

	ntsd.Header.Describe(indent + 1)

	if ntsd.Header.OffsetOwner != 0 {
		fmt.Printf("%s<Owner>\n", strings.Repeat(" │ ", indent+1))
		ntsd.Owner.Describe(indent + 2)
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	}

	if ntsd.Header.OffsetGroup != 0 {
		fmt.Printf("%s<Group>\n", strings.Repeat(" │ ", indent+1))
		ntsd.Group.Describe(indent + 2)
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	}

	if ntsd.Header.OffsetSacl > ntsd.Header.OffsetDacl {
		// Print DACL
		if len(ntsd.DACL.Entries) > 0 {
			ntsd.DACL.Describe(indent + 1)
		} else {
			fmt.Printf("%s<DiscretionaryAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
			fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
		}

		// Print SACL
		if len(ntsd.SACL.Entries) > 0 {
			ntsd.SACL.Describe(indent + 1)
		} else {
			fmt.Printf("%s<SystemAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
			fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
		}
	} else {
		// Print SACL
		if len(ntsd.SACL.Entries) > 0 {
			ntsd.SACL.Describe(indent + 1)
		} else {
			fmt.Printf("%s<SystemAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
			fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
		}

		// Print DACL
		if len(ntsd.DACL.Entries) > 0 {
			ntsd.DACL.Describe(indent + 1)
		} else {
			fmt.Printf("%s<DiscretionaryAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
			fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
		}
	}

	fmt.Println(" └─")
}
