package identity

import (
	"fmt"

	"github.com/TheManticoreProject/winacl/sid"
	"github.com/TheManticoreProject/winacl/utils/describe"
)

// Identity represents a user identity, including its name and associated Security Identifier (SID).
//
// Attributes:
//   - Name (string): The name of the identity, typically representing a user or group.
//   - SID (SID): The Security Identifier associated with the identity, used for access control.
//
// Internal attributes:
//   - RawBytes ([]byte): The raw byte data representing the identity, including the SID information.
//   - RawBytesSize (uint32): The size of the raw byte data.
type Identity struct {
	Name string
	SID  sid.SID

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Unmarshal populates the Identity struct by parsing the provided raw byte slice.
// It extracts the SID from the raw bytes and attempts to assign a name if the SID is well-known.
//
// Parameters:
//   - RawBytes ([]byte): The raw byte data containing the SID information.
func (identity *Identity) Unmarshal(marshalledData []byte) (int, error) {
	identity.RawBytes = marshalledData
	identity.RawBytesSize = 0

	_, err := identity.SID.Unmarshal(marshalledData)
	if err != nil {
		return 0, err
	}
	identity.RawBytesSize = identity.SID.RawBytesSize

	sidString := identity.SID.ToString()
	if name, exists := sid.WellKnownSIDs[sidString]; exists {
		identity.Name = name
	}

	return int(identity.RawBytesSize), nil
}

// Marshal serializes the Identity struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the Identity.
func (identity *Identity) Marshal() ([]byte, error) {
	marshalledData := []byte{}

	bytesStream, err := identity.SID.Marshal()
	if err != nil {
		return nil, err
	}
	marshalledData = append(marshalledData, bytesStream...)

	return marshalledData, nil
}

// Describe prints a detailed description of the Identity struct, including its SID and name,
// formatted with indentation for clarity.
//
// Parameters:
//   - indent (int): The indentation level for formatting the output. Each level increases
//     the indentation depth, allowing for a hierarchical display of the Identity's components.
//
// DescribeList returns the Identity description as a list of lines at
// indentation depth 0.
func (identity *Identity) DescribeList() []string {
	return []string{
		"<Identity>",
		fmt.Sprintf(" │ \x1b[93mSID\x1b[0m  : \x1b[96m%s\x1b[0m", identity.SID.ToString()),
		fmt.Sprintf(" │ \x1b[93mName\x1b[0m : '\x1b[94m%s\x1b[0m'", identity.Name),
		" └─",
	}
}

// DescribeWithCallback renders the Identity at the given indentation depth,
// routing each line to the provided fmt.Printf-like callback.
func (identity *Identity) DescribeWithCallback(indent int, printf describe.Printf) {
	describe.WithCallback(indent, identity.DescribeList(), printf)
}

func (identity *Identity) Describe(indent int) {
	identity.DescribeWithCallback(indent, describe.Printfln)
}
