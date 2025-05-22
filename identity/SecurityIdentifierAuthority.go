package identity

import "encoding/binary"

// SID authority constants define the various authorities used in Security Identifiers (SIDs),
// represented as hexadecimal values.
//
// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c6ce4275-3d90-4890-ab3a-514745e4637e
const (
	SID_AUTHORITY_NULL                      = 0x000000000000
	SID_AUTHORITY_WORLD                     = 0x000000000001
	SID_AUTHORITY_LOCAL                     = 0x000000000002
	SID_AUTHORITY_CREATOR                   = 0x000000000003
	SID_AUTHORITY_NON_UNIQUE                = 0x000000000004
	SID_AUTHORITY_SECURITY_NT               = 0x000000000005
	SID_AUTHORITY_SECURITY_APP_PACKAGE      = 0x00000000000f
	SID_AUTHORITY_SECURITY_MANDATORY_LABEL  = 0x000000000010
	SID_AUTHORITY_SECURITY_SCOPED_POLICY_ID = 0x000000000011
	SID_AUTHORITY_SECURITY_AUTHENTICATION   = 0x000000000012
)

// sidAuthorityNames maps integer constants representing various security identifier (SID) authorities
// to their corresponding human-readable names.
//
// Usage:
//
//	This map allows for quick lookup of a SID authority's name by its integer identifier, aiding in
//	the readability and interpretation of SID authorities.
var SIDAuthorityNames = map[uint64]string{
	SID_AUTHORITY_NULL:                      "Null",
	SID_AUTHORITY_WORLD:                     "World",
	SID_AUTHORITY_LOCAL:                     "Local",
	SID_AUTHORITY_CREATOR:                   "Creator",
	SID_AUTHORITY_NON_UNIQUE:                "Non Unique",
	SID_AUTHORITY_SECURITY_NT:               "NT\\Authority",
	SID_AUTHORITY_SECURITY_APP_PACKAGE:      "App Package",
	SID_AUTHORITY_SECURITY_MANDATORY_LABEL:  "Security Mandatory Label",
	SID_AUTHORITY_SECURITY_SCOPED_POLICY_ID: "Security Scoped Policy ID",
	SID_AUTHORITY_SECURITY_AUTHENTICATION:   "Security Authentication",
}

// SecurityIdentifierAuthority represents an authority within a Security Identifier (SID),
// containing a human-readable name and an integer value.
//
// Fields:
//   - Name: A string representing the name of the authority.
//   - Value: An integer that uniquely identifies the authority.
type SecurityIdentifierAuthority struct {
	Value uint64
}

// Unmarshal assigns a value and a name to the SecurityIdentifierAuthority (SIA) instance
// based on the provided integer flag value.
//
// Parameters:
//   - marshalledData ([]byte): The byte slice containing the serialized data
//     representing the SIA. This data is typically defined by the Windows
//     model and indicates the type of access control entry.
//
// Behavior:
//   - Sets the `Value` field of the SIA instance to `flagValue`.
//   - Attempts to retrieve a corresponding name from the `sidAuthorityNames` map.
//     If found, assigns the retrieved name to the `Name` field.
//     If not found, assigns a default value of "?" to `Name`.
func (sia *SecurityIdentifierAuthority) Unmarshal(marshalledData []byte) (int, error) {
	sia.Value = 0
	sia.Value += uint64(binary.BigEndian.Uint16(marshalledData[0:2])) << 32
	sia.Value += uint64(binary.BigEndian.Uint16(marshalledData[2:4])) << 16
	sia.Value += uint64(binary.BigEndian.Uint16(marshalledData[4:6]))

	return 6, nil
}

// ToBytes converts the current SecurityIdentifierAuthority struct into its binary representation as a byte slice,
// suitable for storage or transmission.
//
// Returns:
//   - []byte: A byte slice representing the SecurityIdentifierAuthority in binary format, constructed from its fields.
func (sia *SecurityIdentifierAuthority) Marshal() ([]byte, error) {
	identifierBytes := make([]byte, 6)

	binary.BigEndian.PutUint16(identifierBytes[0:2], uint16(sia.Value>>32))
	binary.BigEndian.PutUint16(identifierBytes[2:4], uint16(sia.Value>>16))
	binary.BigEndian.PutUint16(identifierBytes[4:6], uint16(sia.Value))

	return identifierBytes, nil
}

// String returns the name of the authority as a string.
//
// Returns:
//   - A string representing the name of the authority.
//   - If the authority is not found in the sidAuthorityNames map, returns "?".
func (sia *SecurityIdentifierAuthority) String() string {
	if name, found := SIDAuthorityNames[sia.Value]; found {
		return name
	}
	return "?"
}
