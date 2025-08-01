package ace

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/ace/header"
	"github.com/TheManticoreProject/winacl/ace/mask"
	"github.com/TheManticoreProject/winacl/identity"
	"github.com/TheManticoreProject/winacl/object"
)

// AccessControlEntry represents an entry in an access control list (ACL).
type AccessControlEntry struct {
	Index                   uint16
	Header                  header.AccessControlEntryHeader
	Mask                    mask.AccessControlMask
	Identity                identity.Identity
	AccessControlObjectType object.AccessControlObjectType

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Unmarshal initializes the AccessControlEntry struct by parsing the raw byte slice.
// It sets the RawBytes and RawBytesSize fields, parses the header, and then parses the ACE.
//
// Parameters:
//   - rawBytes ([]byte): The raw byte slice to be parsed.
func (ace *AccessControlEntry) Unmarshal(marshalledData []byte) (int, error) {
	ace.RawBytesSize = 0

	// Parse Header
	rawBytesSize, err := ace.Header.Unmarshal(marshalledData)
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal Header: %w", err)
	}
	ace.RawBytesSize += uint32(rawBytesSize)

	if int(ace.Header.Size) > len(marshalledData) {
		return 0, fmt.Errorf("failed to unmarshal ACE: ace.Header.Size (%d) is greater than the maximum length of marshalledData (%d)", ace.Header.Size, len(marshalledData))
	}

	// Update rawBytes to only contain the ACE data
	ace.RawBytes = marshalledData[:ace.Header.Size]
	marshalledData = marshalledData[ace.RawBytesSize:ace.Header.Size]

	switch ace.Header.Type.Value {
	case acetype.ACE_TYPE_ACCESS_ALLOWED:
		// Parsing ACE of type ACCESS_ALLOWED_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err := ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

	case acetype.ACE_TYPE_ACCESS_DENIED:
		// Parsing ACE of type ACCESS_DENIED_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/b1e1321d-5816-4513-be67-b65d8ae52fe8

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

	case acetype.ACE_TYPE_SYSTEM_AUDIT:
		// Parsing ACE of type SYSTEM_AUDIT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/9431fd0f-5b9a-47f0-b3f0-3015e2d0d4f9

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

	case acetype.ACE_TYPE_SYSTEM_ALARM:
		// Parsing ACE of type SYSTEM_ALARM_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

	case acetype.ACE_TYPE_ACCESS_ALLOWED_COMPOUND:
		// Parsing ACE of type ACCESS_ALLOWED_COMPOUND_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

	case acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT:
		// Parsing ACE of type ACCESS_ALLOWED_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		rawBytesSize, err = ace.AccessControlObjectType.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal AccessControlObjectType: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

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
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

	case acetype.ACE_TYPE_ACCESS_DENIED_OBJECT:
		// Parsing ACE of type ACCESS_DENIED_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/8720fcf3-865c-4557-97b1-0b3489a6c270

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		rawBytesSize, err = ace.AccessControlObjectType.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal AccessControlObjectType: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

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
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

	case acetype.ACE_TYPE_SYSTEM_AUDIT_OBJECT:
		// Parsing ACE of type SYSTEM_AUDIT_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c8da72ae-6b54-4a05-85f4-e2594936d3d5

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		rawBytesSize, err = ace.AccessControlObjectType.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal AccessControlObjectType: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

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
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary
	case acetype.ACE_TYPE_SYSTEM_ALARM_OBJECT:
		// Parsing ACE of type SYSTEM_ALARM_OBJECT_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

	case acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK:
		// Parsing ACE of type ACCESS_ALLOWED_CALLBACK_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c9579cf4-0f4a-44f1-9444-422dfb10557a

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case acetype.ACE_TYPE_ACCESS_DENIED_CALLBACK:
		// Parsing ACE of type ACCESS_DENIED_CALLBACK_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/35adad6b-fda5-4cc1-b1b5-9beda5b07d2e

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT:
		// Parsing ACE of type ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/fe1838ea-ea34-4a5e-b40e-eb870f8322ae

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		rawBytesSize, err = ace.AccessControlObjectType.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal AccessControlObjectType: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

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
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case acetype.ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT:
		// Parsing ACE of type ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/4652f211-82d5-4b90-bd58-43bf3b0fc48d

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		rawBytesSize, err = ace.AccessControlObjectType.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal AccessControlObjectType: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

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
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case acetype.ACE_TYPE_SYSTEM_AUDIT_CALLBACK:
		// Parsing ACE of type SYSTEM_AUDIT_CALLBACK_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/bd6b6fd8-4bef-427e-9a43-b9b46457e934

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case acetype.ACE_TYPE_SYSTEM_ALARM_CALLBACK:
		// Parsing ACE of type SYSTEM_ALARM_CALLBACK_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
		// No parsing required as it is reserved for future use.

	case acetype.ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
		// Parsing ACE of type SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/bd6b6fd8-4bef-427e-9a43-b9b46457e934

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		rawBytesSize, err = ace.AccessControlObjectType.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal AccessControlObjectType: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

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
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case acetype.ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT:
		// Parsing ACE of type SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
		// No parsing required as it is reserved for future use.

	case acetype.ACE_TYPE_SYSTEM_MANDATORY_LABEL:
		// Parsing ACE of type SYSTEM_MANDATORY_LABEL_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/25fa6565-6cb0-46ab-a30a-016b32c4939a

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

	case acetype.ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
		// Parsing ACE of type SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/352944c7-4fb6-4988-8036-0a25dcedc730

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case acetype.ACE_TYPE_SYSTEM_SCOPED_POLICY_ID:
		// Parsing ACE of type SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/aa0c0f62-4b4c-44f0-9718-c266a6accd9f

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		rawBytesSize, err = ace.Mask.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Mask: %w", err)
		}
		marshalledData = marshalledData[rawBytesSize:]
		ace.RawBytesSize += uint32(rawBytesSize)

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		rawBytesSize, err = ace.Identity.Unmarshal(marshalledData)
		if err != nil {
			return 0, fmt.Errorf("failed to unmarshal Identity: %w", err)
		}
		ace.RawBytesSize += uint32(rawBytesSize)

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	default:
		// Unknown ACE type
		return 0, fmt.Errorf("unknown ACE type: %d", ace.Header.Type.Value)
	}

	return int(ace.RawBytesSize), nil
}

// Marshal serializes the AccessControlEntry struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the ACE.
func (ace *AccessControlEntry) Marshal() ([]byte, error) {
	marshalledData := make([]byte, 0)

	var err error
	var bytesStream []byte

	switch ace.Header.Type.Value {

	case acetype.ACE_TYPE_ACCESS_ALLOWED:
		bytesStream, err = ace.Mask.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Mask: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.Identity.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Identity: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

	case acetype.ACE_TYPE_ACCESS_DENIED:
		bytesStream, err = ace.Mask.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Mask: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.Identity.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Identity: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

	case acetype.ACE_TYPE_SYSTEM_AUDIT:
		bytesStream, err = ace.Mask.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Mask: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.Identity.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Identity: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

	case acetype.ACE_TYPE_SYSTEM_ALARM:
	case acetype.ACE_TYPE_ACCESS_ALLOWED_COMPOUND:
	case acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT:
		bytesStream, err = ace.Mask.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Mask: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.AccessControlObjectType.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal AccessControlObjectType: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.Identity.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Identity: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

	case acetype.ACE_TYPE_ACCESS_DENIED_OBJECT:
		bytesStream, err = ace.Mask.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Mask: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.AccessControlObjectType.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal AccessControlObjectType: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.Identity.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Identity: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

	case acetype.ACE_TYPE_SYSTEM_AUDIT_OBJECT:
		bytesStream, err = ace.Mask.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Mask: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.AccessControlObjectType.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal AccessControlObjectType: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.Identity.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Identity: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

	case acetype.ACE_TYPE_SYSTEM_ALARM_OBJECT:
	case acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK:
		bytesStream, err = ace.Mask.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Mask: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.Identity.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Identity: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

	case acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT:
		bytesStream, err = ace.Mask.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Mask: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.AccessControlObjectType.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal AccessControlObjectType: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.Identity.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Identity: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

	case acetype.ACE_TYPE_ACCESS_DENIED_CALLBACK:
		bytesStream, err = ace.Mask.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Mask: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.Identity.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Identity: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

	case acetype.ACE_TYPE_SYSTEM_ALARM_CALLBACK:
	case acetype.ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
		bytesStream, err = ace.Mask.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Mask: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.AccessControlObjectType.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal AccessControlObjectType: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.Identity.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Identity: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

	case acetype.ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT:
	case acetype.ACE_TYPE_SYSTEM_MANDATORY_LABEL:
		bytesStream, err = ace.Mask.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Mask: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.Identity.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Identity: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

	case acetype.ACE_TYPE_SYSTEM_SCOPED_POLICY_ID:
		bytesStream, err = ace.Mask.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Mask: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)

		bytesStream, err = ace.Identity.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Identity: %w", err)
		}
		marshalledData = append(marshalledData, bytesStream...)
	}

	// Pad the marshalled data to the size specified in the ACE header
	headerSize := 4
	if ace.Header.Size > uint16(len(marshalledData)+headerSize) {
		// Pad the marshalled data to the size specified in the ACE header
		for uint32(len(marshalledData)+headerSize) < uint32(ace.Header.Size) {
			marshalledData = append(marshalledData, 0)
		}
	} else {
		ace.Header.Size = uint16(len(marshalledData) + headerSize)
	}

	// Marshal Header and append at start of marshalled data
	bytesStream, err = ace.Header.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Header: %w", err)
	}
	marshalledData = append(bytesStream, marshalledData...)

	return marshalledData, nil
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

	case acetype.ACE_TYPE_ACCESS_ALLOWED:
		ace.Mask.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_ACCESS_DENIED:
		ace.Mask.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_SYSTEM_AUDIT:
		ace.Mask.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_SYSTEM_ALARM:
	case acetype.ACE_TYPE_ACCESS_ALLOWED_COMPOUND:
	case acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_ACCESS_DENIED_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_SYSTEM_AUDIT_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_SYSTEM_ALARM_OBJECT:
	case acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK:
		ace.Mask.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_ACCESS_DENIED_CALLBACK:
		ace.Mask.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_SYSTEM_AUDIT_CALLBACK:
		ace.Mask.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_SYSTEM_ALARM_CALLBACK:
	case acetype.ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT:
	case acetype.ACE_TYPE_SYSTEM_MANDATORY_LABEL:
		ace.Mask.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
		ace.Mask.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)

	case acetype.ACE_TYPE_SYSTEM_SCOPED_POLICY_ID:
		ace.Mask.Describe(indent + 1)
		ace.Identity.Describe(indent + 1)
	}

	fmt.Printf("%s └─\n", indentPrompt)
}
