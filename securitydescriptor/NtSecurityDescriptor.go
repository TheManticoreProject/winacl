package securitydescriptor

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/winacl/acl"
	"github.com/TheManticoreProject/winacl/identity"
	"github.com/TheManticoreProject/winacl/securitydescriptor/header"
)

// NtSecurityDescriptor represents a Windows security descriptor.
type NtSecurityDescriptor struct {
	Header header.NtSecurityDescriptorHeader

	Owner *identity.Identity
	Group *identity.Identity

	DACL *acl.DiscretionaryAccessControlList
	SACL *acl.SystemAccessControlList

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
		if ntsd.Header.OffsetOwner < uint32(len(ntsd.RawBytes)) {
			if ntsd.Owner == nil {
				ntsd.Owner = &identity.Identity{}
			}
			rawBytesSize, err := ntsd.Owner.Unmarshal(ntsd.RawBytes[ntsd.Header.OffsetOwner:])
			if err != nil {
				return 0, fmt.Errorf("failed to unmarshal Owner: %w", err)
			}
			ntsd.RawBytesSize += uint32(rawBytesSize)
		} else {
			return 0, fmt.Errorf("failed to unmarshal Owner: offset is out of bounds OffsetOwner=%d, RawBytesSize=%d", ntsd.Header.OffsetOwner, ntsd.RawBytesSize)
		}
	}

	// Unmarshal Group if present
	if ntsd.Header.OffsetGroup != 0 {
		if ntsd.Header.OffsetGroup < uint32(len(ntsd.RawBytes)) {
			if ntsd.Group == nil {
				ntsd.Group = &identity.Identity{}
			}
			rawBytesSize, err := ntsd.Group.Unmarshal(ntsd.RawBytes[ntsd.Header.OffsetGroup:])
			if err != nil {
				return 0, fmt.Errorf("failed to unmarshal Group: %w", err)
			}
			ntsd.RawBytesSize += uint32(rawBytesSize)
		} else {
			return 0, fmt.Errorf("failed to unmarshal Group: offset is out of bounds OffsetGroup=%d, RawBytesSize=%d", ntsd.Header.OffsetGroup, ntsd.RawBytesSize)
		}
	}

	// Unmarshal DACL if present
	if ntsd.Header.OffsetDacl != 0 {
		if ntsd.Header.OffsetDacl < uint32(len(ntsd.RawBytes)) {
			if ntsd.DACL == nil {
				ntsd.DACL = &acl.DiscretionaryAccessControlList{}
			}
			rawBytesSize, err := ntsd.DACL.Unmarshal(ntsd.RawBytes[ntsd.Header.OffsetDacl:])
			if err != nil {
				return 0, fmt.Errorf("failed to unmarshal DACL: %w", err)
			}
			ntsd.RawBytesSize += uint32(rawBytesSize)
		} else {
			return 0, fmt.Errorf("failed to unmarshal DACL: offset is out of bounds OffsetDacl=%d, RawBytesSize=%d", ntsd.Header.OffsetDacl, ntsd.RawBytesSize)
		}
	}

	// Unmarshal SACL if present
	if ntsd.Header.OffsetSacl != 0 {
		if ntsd.Header.OffsetSacl < uint32(len(ntsd.RawBytes)) {
			if ntsd.SACL == nil {
				ntsd.SACL = &acl.SystemAccessControlList{}
			}
			rawBytesSize, err := ntsd.SACL.Unmarshal(ntsd.RawBytes[ntsd.Header.OffsetSacl:])
			if err != nil {
				return 0, fmt.Errorf("failed to unmarshal SACL: %w", err)
			}
			ntsd.RawBytesSize += uint32(rawBytesSize)
		} else {
			return 0, fmt.Errorf("failed to unmarshal SACL: offset is out of bounds OffsetSacl=%d, RawBytesSize=%d", ntsd.Header.OffsetSacl, ntsd.RawBytesSize)
		}
	}

	return int(ntsd.RawBytesSize), nil
}

// FromSDDLString initializes the NtSecurityDescriptor struct by parsing the SDDL string.
//
// Parameters:
//   - sddlString (string): The SDDL string to be parsed.
//
// Returns:
//   - error: An error if parsing fails, otherwise nil.
func (ntsd *NtSecurityDescriptor) FromSDDLString(sddlString string) (int, error) {
	return 0, nil
}

// Marshal serializes the NtSecurityDescriptor struct into a byte slice.
//
// Returns:
//   - ([]byte, error): A byte slice containing the serialized data and an error if serialization fails, otherwise nil.
func (ntsd *NtSecurityDescriptor) Marshal() ([]byte, error) {
	// Initialize a byte slice to hold the serialized data
	var err error
	var marshalledData []byte

	offset := 20

	// Marshal SACL
	dataSacl := []byte{}
	if len(ntsd.SACL.Entries) > 0 {
		dataSacl, err = ntsd.SACL.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal SACL: %w", err)
		}
		ntsd.Header.OffsetSacl = uint32(offset)
		offset += len(dataSacl)
	}

	// Marshal DACL
	dataDacl := []byte{}
	if len(ntsd.DACL.Entries) > 0 {
		dataDacl, err = ntsd.DACL.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal DACL: %w", err)
		}
		ntsd.Header.OffsetDacl = uint32(offset)
		offset += len(dataDacl)
	}

	// Marshal Owner
	dataOwner := []byte{}
	if ntsd.Owner != nil {
		dataOwner, err = ntsd.Owner.SID.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Owner: %w", err)
		}
		ntsd.Header.OffsetOwner = uint32(offset)
		offset += len(dataOwner)
	}

	// Marshal Group
	dataGroup := []byte{}
	if ntsd.Group != nil {
		dataGroup, err = ntsd.Group.SID.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Group: %w", err)
		}
		ntsd.Header.OffsetGroup = uint32(offset)
		offset += len(dataGroup)
	}

	// Update the header and append the header bytes
	marshalledData, err = ntsd.Header.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Header: %w", err)
	}

	// Append the SACL bytes if present
	if ntsd.Header.OffsetSacl != 0 {
		marshalledData = append(marshalledData, dataSacl...)
	}
	// Append the DACL bytes if present
	if ntsd.Header.OffsetDacl != 0 {
		marshalledData = append(marshalledData, dataDacl...)
	}
	// Append the Owner SID bytes if present
	if ntsd.Header.OffsetOwner != 0 {
		marshalledData = append(marshalledData, dataOwner...)
	}
	// Append the Group SID bytes if present
	if ntsd.Header.OffsetGroup != 0 {
		marshalledData = append(marshalledData, dataGroup...)
	}

	return marshalledData, nil
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
