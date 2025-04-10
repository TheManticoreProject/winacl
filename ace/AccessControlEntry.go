package ace

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/TheManticoreProject/winacl/identity"
	"github.com/TheManticoreProject/winacl/object"
)

// AccessControlEntry represents an entry in an access control list (ACL).
type AccessControlEntry struct {
	Index                   uint16
	Header                  AccessControlEntryHeader
	Mask                    AccessControlMask
	SID                     identity.Identity
	AccessControlObjectType object.AccessControlObjectType
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Parse initializes the AccessControlEntry struct by parsing the raw byte slice.
// It sets the RawBytes and RawBytesSize fields, parses the header, and then parses the ACE.
//
// Parameters:
//   - rawBytes ([]byte): The raw byte slice to be parsed.
func (ace *AccessControlEntry) Parse(rawBytes []byte) {
	debug := false

	ace.RawBytesSize = 0
	// Parse Header
	ace.Header.Parse(rawBytes)
	ace.RawBytesSize = uint32(ace.Header.Size)

	// Update rawBytes to only contain the ACE data
	ace.RawBytes = rawBytes[:ace.Header.Size]
	rawBytes = rawBytes[ace.Header.RawBytesSize:ace.Header.Size]

	if debug {
		fmt.Printf("[debug][AccessControlEntry.Parse()] ACE Type: %s\n", AccessControlEntryTypeValueToName[ace.Header.Type.Value])
		fmt.Printf("[debug][AccessControlEntry.Parse()] rawBytes: %s\n", hex.EncodeToString(ace.RawBytes))
	}
	switch ace.Header.Type.Value {
	case ACE_TYPE_ACCESS_ALLOWED:
		// Parsing ACE of type ACCESS_ALLOWED_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

	case ACE_TYPE_ACCESS_DENIED:
		// Parsing ACE of type ACCESS_DENIED_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/b1e1321d-5816-4513-be67-b65d8ae52fe8

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

	case ACE_TYPE_SYSTEM_AUDIT:
		// Parsing ACE of type SYSTEM_AUDIT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/9431fd0f-5b9a-47f0-b3f0-3015e2d0d4f9

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

	case ACE_TYPE_SYSTEM_ALARM:
		// Parsing ACE of type SYSTEM_ALARM_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

	case ACE_TYPE_ACCESS_ALLOWED_COMPOUND:
		// Parsing ACE of type ACCESS_ALLOWED_COMPOUND_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

	case ACE_TYPE_ACCESS_ALLOWED_OBJECT:
		// Parsing ACE of type ACCESS_ALLOWED_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		ace.AccessControlObjectType.Parse(rawBytes)
		rawBytes = rawBytes[ace.AccessControlObjectType.RawBytesSize:]
		// ace.RawBytesSize += ace.AccessControlObjectType.RawBytesSize
		// Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
		// indicate whether the ObjectType and InheritedObjectType fields contain valid data.
		// This parameter can be one or more of the following values.

		// ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
		// or type of child object. The purpose of this GUID depends on the user rights specified
		// in the Mask field. This field is valid only if the ACE_OBJECT_TYPE_PRESENT bit is set
		// in the Flags field. Otherwise, the ObjectType field is ignored.

		// InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
		// can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
		// ACE_HEADER, as well as by any protection against inheritance placed on the child
		// objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
		// in the Flags member. Otherwise, the InheritedObjectType field is ignored.

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

	case ACE_TYPE_ACCESS_DENIED_OBJECT:
		// Parsing ACE of type ACCESS_DENIED_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/8720fcf3-865c-4557-97b1-0b3489a6c270

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		ace.AccessControlObjectType.Parse(rawBytes)
		rawBytes = rawBytes[ace.AccessControlObjectType.RawBytesSize:]
		// ace.RawBytesSize += ace.AccessControlObjectType.RawBytesSize
		// Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
		// indicate whether the ObjectType and InheritedObjectType fields contain valid data.
		// This parameter can be one or more of the following values.

		// ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
		// or type of child object. The purpose of this GUID depends on the user rights specified
		// in the Mask field. This field is valid only if the ACE_OBJECT_TYPE_PRESENT bit is set
		// in the Flags field. Otherwise, the ObjectType field is ignored.

		// InheritedObjectType (16 bytes): A GU075a38002000000003000000be3b0ef3f09fd111b6030000f80367c1a57a96bfe60dd011a28500aa003049e20101000000000001ID that identifies the type of child object that
		// can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
		// ACE_HEADER, as well as by any protection against inheritance placed on the child
		// objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
		// in the Flags member. Otherwise, the InheritedObjectType field is ignored.

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

	case ACE_TYPE_SYSTEM_AUDIT_OBJECT:
		// Parsing ACE of type SYSTEM_AUDIT_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c8da72ae-6b54-4a05-85f4-e2594936d3d5

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		ace.AccessControlObjectType.Parse(rawBytes)
		rawBytes = rawBytes[ace.AccessControlObjectType.RawBytesSize:]
		// ace.RawBytesSize += ace.AccessControlObjectType.RawBytesSize
		// Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
		// indicate whether the ObjectType and InheritedObjectType fields contain valid data.
		// This parameter can be one or more of the following values.

		// ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
		// or type of child object. The purpose of this GUID depends on the user rights specified
		// in the Mask field. This field is valid only if the ACE_OBJECT_TYPE_PRESENT bit is set
		// in the Flags field. Otherwise, the ObjectType field is ignored.

		// InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
		// can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
		// ACE_HEADER, as well as by any protection against inheritance placed on the child
		// objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
		// in the Flags member. Otherwise, the InheritedObjectType field is ignored.

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary
	case ACE_TYPE_SYSTEM_ALARM_OBJECT:
		// Parsing ACE of type SYSTEM_ALARM_OBJECT_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK:
		// Parsing ACE of type ACCESS_ALLOWED_CALLBACK_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c9579cf4-0f4a-44f1-9444-422dfb10557a

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_ACCESS_DENIED_CALLBACK:
		// Parsing ACE of type ACCESS_DENIED_CALLBACK_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/35adad6b-fda5-4cc1-b1b5-9beda5b07d2e

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT:
		// Parsing ACE of type ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
		// Source:

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		ace.AccessControlObjectType.Parse(rawBytes)
		rawBytes = rawBytes[ace.AccessControlObjectType.RawBytesSize:]
		// ace.RawBytesSize += ace.AccessControlObjectType.RawBytesSize
		// Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
		// indicate whether the ObjectType and InheritedObjectType fields contain valid data.
		// This parameter can be one or more of the following values.

		// ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
		// or type of child object. The purpose of this GUID depends on the user rights specified
		// in the Mask field. This field is valid only if the ACE_OBJECT_TYPE_PRESENT bit is set
		// in the Flags field. Otherwise, the ObjectType field is ignored.

		// InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
		// can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
		// ACE_HEADER, as well as by any protection against inheritance placed on the child
		// objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
		// in the Flags member. Otherwise, the InheritedObjectType field is ignored.

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT:
		// Parsing ACE of type ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
		// Source:

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		ace.AccessControlObjectType.Parse(rawBytes)
		rawBytes = rawBytes[ace.AccessControlObjectType.RawBytesSize:]
		// ace.RawBytesSize += ace.AccessControlObjectType.RawBytesSize
		// Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
		// indicate whether the ObjectType and InheritedObjectType fields contain valid data.
		// This parameter can be one or more of the following values.

		// ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
		// or type of child object. The purpose of this GUID depends on the user rights specified
		// in the Mask field. This field is valid only if the ACE_OBJECT_TYPE_PRESENT bit is set
		// in the Flags field. Otherwise, the ObjectType field is ignored.

		// InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
		// can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
		// ACE_HEADER, as well as by any protection against inheritance placed on the child
		// objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
		// in the Flags member. Otherwise, the InheritedObjectType field is ignored.

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_SYSTEM_AUDIT_CALLBACK:
		// Parsing ACE of type SYSTEM_AUDIT_CALLBACK_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/bd6b6fd8-4bef-427e-9a43-b9b46457e934

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_SYSTEM_ALARM_CALLBACK:
		// Parsing ACE of type SYSTEM_ALARM_CALLBACK_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
		// No parsing required as it is reserved for future use.

	case ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
		// Parsing ACE of type SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/bd6b6fd8-4bef-427e-9a43-b9b46457e934

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		ace.AccessControlObjectType.Parse(rawBytes)
		rawBytes = rawBytes[ace.AccessControlObjectType.RawBytesSize:]
		// ace.RawBytesSize += ace.AccessControlObjectType.RawBytesSize
		// Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
		// indicate whether the ObjectType and InheritedObjectType fields contain valid data.
		// This parameter can be one or more of the following values.

		// ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
		// or type of child object. The purpose of this GUID depends on the user rights specified
		// in the Mask field. This field is valid only if the ACE_OBJECT_TYPE_PRESENT bit is set
		// in the Flags field. Otherwise, the ObjectType field is ignored.

		// InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
		// can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
		// ACE_HEADER, as well as by any protection against inheritance placed on the child
		// objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
		// in the Flags member. Otherwise, the InheritedObjectType field is ignored.

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT:
		// Parsing ACE of type SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
		// No parsing required as it is reserved for future use.

	case ACE_TYPE_SYSTEM_MANDATORY_LABEL:
		// Parsing ACE of type SYSTEM_MANDATORY_LABEL_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/25fa6565-6cb0-46ab-a30a-016b32c4939a

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

	case ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
		// Parsing ACE of type SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/352944c7-4fb6-4988-8036-0a25dcedc730

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_SYSTEM_SCOPED_POLICY_ID:
		// Parsing ACE of type SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/aa0c0f62-4b4c-44f0-9718-c266a6accd9f

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(rawBytes)
		rawBytes = rawBytes[ace.Mask.RawBytesSize:]
		// ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(rawBytes)
		// ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	default:
		//
	}
}

// ToBytes serializes the AccessControlEntry struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the ACE.
func (ace *AccessControlEntry) ToBytes() []byte {
	serializedData := make([]byte, 0)

	serializedData = append(serializedData, ace.Header.ToBytes()...)

	switch ace.Header.Type.Value {
	case ACE_TYPE_ACCESS_ALLOWED:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_ACCESS_DENIED:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_SYSTEM_AUDIT:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_SYSTEM_ALARM:
	case ACE_TYPE_ACCESS_ALLOWED_COMPOUND:
	case ACE_TYPE_ACCESS_ALLOWED_OBJECT:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.AccessControlObjectType.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_ACCESS_DENIED_OBJECT:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.AccessControlObjectType.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_SYSTEM_AUDIT_OBJECT:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.AccessControlObjectType.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_SYSTEM_ALARM_OBJECT:
	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_ACCESS_DENIED_CALLBACK:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.AccessControlObjectType.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.AccessControlObjectType.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_SYSTEM_AUDIT_CALLBACK:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_SYSTEM_ALARM_CALLBACK:
	case ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.AccessControlObjectType.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT:
	case ACE_TYPE_SYSTEM_MANDATORY_LABEL:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	case ACE_TYPE_SYSTEM_SCOPED_POLICY_ID:
		serializedData = append(serializedData, ace.Mask.ToBytes()...)
		serializedData = append(serializedData, ace.SID.ToBytes()...)
	}

	for uint32(len(serializedData)) < uint32(ace.Header.Size) {
		serializedData = append(serializedData, 0)
	}

	return serializedData
}

// IsInherited checks whether the Access Control Entry (ACE) is inherited
// from a parent object. This is determined by checking if the ACE_FLAG_INHERITED
// is present in the Flags.Values slice of the ACE header.
//
// Returns:
// - bool: true if the ACE is inherited, false otherwise.
func (ace *AccessControlEntry) IsInherited() bool {
	return slices.Contains(ace.Header.Flags.Values, ACE_FLAG_INHERITED)
}

// HasFlag checks if a specific flag is set within the ACE's flags.
//
// Parameters:
// - flag: The integer value of the flag to check.
//
// Returns:
// - bool: true if the specified flag is set, false otherwise.
func (ace *AccessControlEntry) HasFlag(flag uint8) bool {
	return slices.Contains(ace.Header.Flags.Values, flag)
}

// Describe prints a detailed description of the AccessControlEntry struct,
// including its attributes formatted with indentation for clarity.
//
// Parameters:
//   - indent (int): The indentation level for formatting the output. Each level increases
//     the indentation depth, allowing for a hierarchical display of the ACE's components.
func (ace *AccessControlEntry) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<AccessControlEntry #%d>\n", indentPrompt, ace.Index)
	ace.Header.Describe(indent + 1)

	switch ace.Header.Type.Value {
	case ACE_TYPE_ACCESS_ALLOWED:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_ACCESS_DENIED:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_AUDIT:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_ALARM:
	case ACE_TYPE_ACCESS_ALLOWED_COMPOUND:
	case ACE_TYPE_ACCESS_ALLOWED_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_ACCESS_DENIED_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_AUDIT_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_ALARM_OBJECT:
	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_ACCESS_DENIED_CALLBACK:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_AUDIT_CALLBACK:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_ALARM_CALLBACK:
	case ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT:
	case ACE_TYPE_SYSTEM_MANDATORY_LABEL:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_SCOPED_POLICY_ID:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	}

	fmt.Printf("%s └─\n", indentPrompt)
}
