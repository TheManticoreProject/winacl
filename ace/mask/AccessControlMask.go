package mask

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/TheManticoreProject/winacl/rights"
	"github.com/TheManticoreProject/winacl/utils/describe"
)

// AccessControlMask represents a mask for access control entries.
// It contains the raw value, a list of individual flags represented as uint32 values,
// and their corresponding names for better readability.
type AccessControlMask struct {
	RawValue uint32   // The raw value of the access control mask
	Values   []uint32 // Individual flag values extracted from the mask
	Flags    []string // Names of the flags corresponding to their values

	// Internal fields
	RawBytes     []byte // Raw byte representation of the mask
	RawBytesSize uint32 // Size of the raw bytes
}

// Unmarshal populates the AccessControlMask from raw byte data.
// It extracts the RawValue and determines the corresponding flags and their names.
func (acm *AccessControlMask) Unmarshal(marshalledData []byte) (int, error) {
	if len(marshalledData) < 4 {
		return 0, fmt.Errorf("AccessControlMask unmarshal requires at least 4 bytes, got %d", len(marshalledData))
	}

	// Store exactly the 4 bytes of the ACCESS_MASK (MS-DTYP 2.4.3). The caller
	// passes the whole remaining ACE body (mask + SID + application data), so
	// slicing to [:4] avoids aliasing the variable-length remainder into
	// RawBytes — which otherwise made Equal (a byte comparison of RawBytes)
	// report two identical masks as unequal when their ACE tails differed.
	acm.RawBytes = marshalledData[:4]
	acm.RawBytesSize = 4

	// Convert raw bytes to a uint32 value using little-endian format
	acm.RawValue = binary.LittleEndian.Uint32(marshalledData[:4])

	// Prepare a list of right names and sort them for consistent ordering
	listOfRightNames := make([]string, 0, len(rights.RightValueToRightName))
	for _, RightName := range rights.RightValueToRightName {
		listOfRightNames = append(listOfRightNames, RightName)
	}
	sort.Strings(listOfRightNames)

	// Initialize slices for flags and values
	acm.Flags = make([]string, 0)
	acm.Values = make([]uint32, 0)

	// Parse flags based on the sorted right names
	for _, RightName := range listOfRightNames {
		RightValue := rights.RightNameToRightValue[RightName]
		// Check if the corresponding right is set in the RawValue
		if (acm.RawValue & RightValue) == RightValue {
			acm.Flags = append(acm.Flags, RightName)    // Add the name of the right
			acm.Values = append(acm.Values, RightValue) // Add the value of the right
		}
	}

	return 4, nil
}

// Marshal serializes the AccessControlMask struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the AccessControlMask.
func (acm *AccessControlMask) Marshal() ([]byte, error) {
	marshalledData := make([]byte, 4)

	binary.LittleEndian.PutUint32(marshalledData, acm.RawValue)

	return marshalledData, nil
}

// String returns a string representation of the AccessControlMask.
//
// Returns:
//   - string: The string representation of the AccessControlMask.
func (acm *AccessControlMask) String() string {
	return strings.Join(acm.Flags, "|")
}

// DescribeList returns the AccessControlMask description as a list of lines at
// indentation depth 0.
func (acm *AccessControlMask) DescribeList() []string {
	return []string{
		"<AccessControlMask>",
		fmt.Sprintf(" │ \x1b[93mMask\x1b[0m : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)", acm.RawValue, acm.String()),
		" └─",
	}
}

// DescribeWithCallback renders the AccessControlMask at the given indentation
// depth, routing each line to the provided fmt.Printf-like callback.
func (acm *AccessControlMask) DescribeWithCallback(indent int, printf describe.Printf) {
	describe.WithCallback(indent, acm.DescribeList(), printf)
}

// Describe outputs the AccessControlMask details in a formatted manner.
// It displays the raw mask value and the associated flags.
func (acm *AccessControlMask) Describe(indent int) {
	acm.DescribeWithCallback(indent, describe.Printfln)
}
