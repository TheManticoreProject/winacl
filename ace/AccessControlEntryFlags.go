package ace

import "strings"

// https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.aceflags?view=net-8.0
const (
	// No ACE flags are set.
	ACE_FLAG_NONE = 0x00
	// Noncontainer child objects inherit the ACE as an effective ACE.
	ACE_FLAG_OBJECT_INHERIT = 0x01
	// Child objects that are containers, such as directories, inherit the
	// ACE as an effective ACE. The inherited ACE is inheritable unless the
	// NO_PROPAGATE_INHERIT_ACE bit flag is also set.
	ACE_FLAG_CONTAINER_INHERIT = 0x02
	// If the ACE is inherited by a child object, the system clears the
	// OBJECT_INHERIT_ACE and CONTAINER_INHERIT_ACE flags in the inherited ACE.
	// This prevents the ACE from being inherited by subsequent generations of
	// objects.
	ACE_FLAG_NO_PROPAGATE_INHERIT = 0x04
	// Indicates an inherit-only ACE, which does not control access to the
	// object to which it is attached. If this flag is not set, the ACE is an
	// effective ACE that controls access to the object to which it is attached.
	ACE_FLAG_INHERITED = 0x10
	// Used to indicate that the ACE was inherited. See section 2.5.3.5 for
	// processing rules for setting this flag.
	ACE_FLAG_SUCCESSFUL_ACCESS = 0x40
	// Used with system-audit ACEs in a system access control list (SACL) to
	// generate audit messages for failed access attempts.
	ACE_FLAG_FAILED_ACCESS = 0x80
	// All access attempts are audited.
	ACE_FLAG_AUDIT_FLAGS = 0xc0
	// Indicates an inherit-only ACE, which does not control access to the object
	// to which it is attached. If this flag is not set, the ACE is an effective
	// ACE that controls access to the object to which it is attached.
	ACE_FLAG_INHERIT_ONLY = 0x08
)

// AccessControlEntryFlag represents an access control entry (ACE) flag.
// It contains the flag's name for easy identification and its corresponding
// integer value, which represents the flag as defined in the Windows
// security model. This struct is useful for managing and interpreting
// access control entries in security descriptors.
//
// Attributes:
//   - Name (string): The name of the access control entry flag, which
//     provides a human-readable description of the flag.
//   - Value (int): The integer value that represents the flag, typically
//     defined by the security model, allowing for bitwise operations to
//     determine permissions and access rights.
type AccessControlEntryFlag struct {
	RawValue uint8
	Values   []uint8
	Flags    []string
}

// Define a map of access control entry flag values to their names.
var AccessControlEntryFlagToName = map[uint8]string{
	ACE_FLAG_NONE:                 "NONE",
	ACE_FLAG_OBJECT_INHERIT:       "OBJECT_INHERIT",
	ACE_FLAG_CONTAINER_INHERIT:    "CONTAINER_INHERIT",
	ACE_FLAG_NO_PROPAGATE_INHERIT: "NO_PROPAGATE_INHERIT",
	ACE_FLAG_INHERIT_ONLY:         "INHERIT_ONLY",
	ACE_FLAG_INHERITED:            "INHERITED",
	ACE_FLAG_SUCCESSFUL_ACCESS:    "SUCCESSFUL_ACCESS",
	ACE_FLAG_FAILED_ACCESS:        "FAILED_ACCESS",
	ACE_FLAG_AUDIT_FLAGS:          "AUDIT_FLAGS",
}

// Parse sets the Value of the AccessControlEntryFlag and looks up its name
// from a predefined map of flag values to names. If the flag value is not
// found in the map, it assigns the name as "?".
//
// Attributes:
//   - flagValue (int): The integer value representing the access control
//     entry flag. This value is typically defined by the Windows security
//     model and determines the permissions or behavior associated with the
//     flag.
func (aceflag *AccessControlEntryFlag) Unmarshal(marshalledData []byte) (int, error) {
	aceflag.RawValue = uint8(marshalledData[0])
	aceflag.Values = []uint8{}
	aceflag.Flags = []string{}

	for flagValue, flagName := range AccessControlEntryFlagToName {
		if (aceflag.RawValue & flagValue) == flagValue {
			aceflag.Values = append(aceflag.Values, flagValue)
			aceflag.Flags = append(aceflag.Flags, flagName)
		}
	}

	return 1, nil
}

// Marshal serializes the AccessControlEntryFlag struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the ACE flag.
func (aceflag *AccessControlEntryFlag) Marshal() ([]byte, error) {
	return []byte{aceflag.RawValue}, nil
}

// String returns a string representation of the AccessControlEntryFlag.
//
// Returns:
//   - string: A string containing the names of the flags that are set in the AccessControlEntryFlag.
func (aceflag *AccessControlEntryFlag) String() string {
	return strings.Join(aceflag.Flags, "|")
}
