package object

import "encoding/binary"

// A set of bit flags that indicate whether the ObjectType and InheritedObjectType members are present. This parameter can be one or more of the following values.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace
const (
	ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE                          = 0x00000000 // Neither ObjectType nor InheritedObjectType are valid.
	ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT           = 0x00000001 // ObjectType is valid.
	ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002 // InheritedObjectType is valid. If this value is not specified, all types of child objects can inherit the ACE.
)

// AccessControlObjectTypeFlags represents the flags for the AccessControlObjectType.
type AccessControlObjectTypeFlags struct {
	Name  string
	Value uint32
}

// Unmarshal sets the Value of the AccessControlObjectTypeFlags and looks up its name
// from a predefined map of ACE types to names. If the ACE type is not found
// in the map, it assigns the name as "?".
//
// Attributes:
//   - RawBytes ([]byte): The byte slice representing the AccessControlObjectTypeFlags.
func (acotype *AccessControlObjectTypeFlags) Unmarshal(rawBytes []byte) (int, error) {
	acotype.Value = binary.LittleEndian.Uint32(rawBytes[0:4])
	return 4, nil
}

// ToBytes serializes the AccessControlObjectTypeFlags struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the AccessControlObjectTypeFlags.
func (acotype *AccessControlObjectTypeFlags) Marshal() ([]byte, error) {
	serializedData := make([]byte, 4)

	binary.LittleEndian.PutUint32(serializedData, acotype.Value)

	return serializedData, nil
}

// String returns a string representation of the AccessControlObjectTypeFlags.
//
// Returns:
//   - string: The string representation of the AccessControlObjectTypeFlags.
func (acotype *AccessControlObjectTypeFlags) String() string {
	if acotype.Value == (ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT | ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) {
		acotype.Name = "OBJECT_TYPE_PRESENT|INHERITED_OBJECT_TYPE_PRESENT"
	} else if acotype.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT {
		acotype.Name = "INHERITED_OBJECT_TYPE_PRESENT"
	} else if acotype.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT {
		acotype.Name = "OBJECT_TYPE_PRESENT"
	} else if acotype.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE {
		acotype.Name = "NONE"
	} else {
		acotype.Name = "?"
	}

	return acotype.Name
}
