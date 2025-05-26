package acetype

const (
	ACE_TYPE_ACCESS_ALLOWED                 uint8 = 0x00 // Access-allowed ACE that uses the ACCESS_ALLOWED_ACE (section 2.4.4.2) structure.
	ACE_TYPE_ACCESS_DENIED                  uint8 = 0x01 // Access-denied ACE that uses the ACCESS_DENIED_ACE (section 2.4.4.4) structure.
	ACE_TYPE_SYSTEM_AUDIT                   uint8 = 0x02 // System-audit ACE that uses the SYSTEM_AUDIT_ACE (section 2.4.4.10) structure.
	ACE_TYPE_SYSTEM_ALARM                   uint8 = 0x03 // Reserved for future use.
	ACE_TYPE_ACCESS_ALLOWED_COMPOUND        uint8 = 0x04 // Reserved for future use.
	ACE_TYPE_ACCESS_ALLOWED_OBJECT          uint8 = 0x05 // Object-specific access-allowed ACE that uses the ACCESS_ALLOWED_OBJECT_ACE (section 2.4.4.3) structure.
	ACE_TYPE_ACCESS_DENIED_OBJECT           uint8 = 0x06 // Object-specific access-denied ACE that uses the ACCESS_DENIED_OBJECT_ACE (section 2.4.4.5) structure.
	ACE_TYPE_SYSTEM_AUDIT_OBJECT            uint8 = 0x07 // Object-specific system-audit ACE that uses the SYSTEM_AUDIT_OBJECT_ACE (section 2.4.4.11) structure.
	ACE_TYPE_SYSTEM_ALARM_OBJECT            uint8 = 0x08 // Reserved for future use.
	ACE_TYPE_ACCESS_ALLOWED_CALLBACK        uint8 = 0x09 // Access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_ACE (section 2.4.4.6) structure.
	ACE_TYPE_ACCESS_DENIED_CALLBACK         uint8 = 0x0A // Access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_ACE (section 2.4.4.7) structure.
	ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT uint8 = 0x0B // Object-specific access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_OBJECT_ACE (section 2.4.4.8) structure.
	ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT  uint8 = 0x0C // Object-specific access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_OBJECT_ACE (section 2.4.4.9) structure.
	ACE_TYPE_SYSTEM_AUDIT_CALLBACK          uint8 = 0x0D // System-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_ACE (section 2.4.4.12) structure.
	ACE_TYPE_SYSTEM_ALARM_CALLBACK          uint8 = 0x0E // Reserved for future use.
	ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT   uint8 = 0x0F // Object-specific system-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_OBJECT_ACE (section 2.4.4.14) structure.
	ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT   uint8 = 0x10 // Reserved for future use.
	ACE_TYPE_SYSTEM_MANDATORY_LABEL         uint8 = 0x11 // Mandatory label ACE that uses the SYSTEM_MANDATORY_LABEL_ACE (section 2.4.4.13) structure.
	ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE      uint8 = 0x12 // Resource attribute ACE that uses the SYSTEM_RESOURCE_ATTRIBUTE_ACE (section 2.4.4.15).
	ACE_TYPE_SYSTEM_SCOPED_POLICY_ID        uint8 = 0x13 // A central policy ID ACE that uses the SYSTEM_SCOPED_POLICY_ID_ACE (section 2.4.4.16).

)

// AccessControlEntryType represents the type of an Access Control Entry (ACE)
// in the security descriptor of an object. Each ACE defines the access rights
// that are granted or denied to a user or group for a specific object.
//
// The struct contains the following fields:
//
// - Name: A string representing the human-readable name of the ACE type.
// - Value: An integer representing the corresponding value of the ACE type.
type AccessControlEntryType struct {
	Value uint8
}

// AccessControlEntryTypeValueToName maps integer values representing Access
// Control Entry (ACE) types to their corresponding string names. This is
// used for easy lookups when interpreting ACE types.
//
// The keys are typically defined constants that correspond to various
// ACE types within the Windows security model, providing a human-readable
// representation of these types.
var AccessControlEntryTypeValueToName = map[uint8]string{
	ACE_TYPE_ACCESS_ALLOWED:                 "ACCESS_ALLOWED",
	ACE_TYPE_ACCESS_DENIED:                  "ACCESS_DENIED",
	ACE_TYPE_SYSTEM_AUDIT:                   "SYSTEM_AUDIT",
	ACE_TYPE_SYSTEM_ALARM:                   "SYSTEM_ALARM",
	ACE_TYPE_ACCESS_ALLOWED_COMPOUND:        "ACCESS_ALLOWED_COMPOUND",
	ACE_TYPE_ACCESS_ALLOWED_OBJECT:          "ACCESS_ALLOWED_OBJECT",
	ACE_TYPE_ACCESS_DENIED_OBJECT:           "ACCESS_DENIED_OBJECT",
	ACE_TYPE_SYSTEM_AUDIT_OBJECT:            "SYSTEM_AUDIT_OBJECT",
	ACE_TYPE_SYSTEM_ALARM_OBJECT:            "SYSTEM_ALARM_OBJECT",
	ACE_TYPE_ACCESS_ALLOWED_CALLBACK:        "ACCESS_ALLOWED_CALLBACK",
	ACE_TYPE_ACCESS_DENIED_CALLBACK:         "ACCESS_DENIED_CALLBACK",
	ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT: "ACCESS_ALLOWED_CALLBACK_OBJECT",
	ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT:  "ACCESS_DENIED_CALLBACK_OBJECT",
	ACE_TYPE_SYSTEM_AUDIT_CALLBACK:          "SYSTEM_AUDIT_CALLBACK",
	ACE_TYPE_SYSTEM_ALARM_CALLBACK:          "SYSTEM_ALARM_CALLBACK",
	ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:   "SYSTEM_AUDIT_CALLBACK_OBJECT",
	ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT:   "SYSTEM_ALARM_CALLBACK_OBJECT",
	ACE_TYPE_SYSTEM_MANDATORY_LABEL:         "SYSTEM_MANDATORY_LABEL",
	ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:      "SYSTEM_RESOURCE_ATTRIBUTE",
	ACE_TYPE_SYSTEM_SCOPED_POLICY_ID:        "SYSTEM_SCOPED_POLICY_ID",
}

// Unmarshal deserializes the AccessControlEntryType struct from a byte slice.
//
// Returns:
//   - int: The number of bytes read from the input slice.
//   - error: An error if the unmarshalling fails.
//
// Attributes:
//   - marshalledData ([]byte): The byte slice containing the serialized data
//     representing the ACE type. This data is typically defined by the Windows
//     model and indicates the type of access control entry.
func (acetype *AccessControlEntryType) Unmarshal(marshalledData []byte) (int, error) {
	// Set the value of the ACE type
	acetype.Value = uint8(marshalledData[0])

	return 1, nil
}

// Marshal serializes the AccessControlEntryType struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the ACE type.
func (acetype *AccessControlEntryType) Marshal() ([]byte, error) {
	return []byte{acetype.Value}, nil
}

// String returns the string representation of the AccessControlEntryType.
// It looks up the name from the map of ACE types to names and returns the corresponding name.
// If the ACE type is not found in the map, it returns "?".
func (acetype *AccessControlEntryType) String() string {
	// Lookup the name from the map, defaulting to "?" if not found
	if name, found := AccessControlEntryTypeValueToName[uint8(acetype.Value)]; found {
		return name
	}
	return "?"
}
