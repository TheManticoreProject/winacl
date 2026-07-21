package object

import (
	"fmt"

	"github.com/TheManticoreProject/winacl/object/flags"
	"github.com/TheManticoreProject/winacl/utils/describe"
)

// AccessControlObjectType represents the access control object type.
type AccessControlObjectType struct {
	Flags               flags.AccessControlObjectTypeFlags
	ObjectType          ObjectType
	InheritedObjectType InheritedObjectType

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Unmarshal parses the AccessControlObjectType from a byte slice.
//
// Attributes:
//   - rawBytes ([]byte): The byte slice to parse the AccessControlObjectType from.
//
// Returns:
//   - int: The size of the parsed AccessControlObjectType in bytes.
//   - error: An error if the parsing fails.
func (aco *AccessControlObjectType) Unmarshal(rawBytes []byte) (int, error) {
	aco.RawBytesSize = 0

	if len(rawBytes) < 4 {
		return 0, fmt.Errorf("AccessControlObjectType unmarshal requires at least 4 bytes, got %d", len(rawBytes))
	}

	rawBytesSize, err := aco.Flags.Unmarshal(rawBytes[0:4])
	if err != nil {
		return 0, err
	}
	aco.RawBytesSize += uint32(rawBytesSize)
	rawBytes = rawBytes[rawBytesSize:]

	if aco.Flags.Value != flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE {
		// Unmarshal OBJECT_TYPE
		if (aco.Flags.Value & flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) == flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT {
			rawBytesSize, err = aco.ObjectType.Unmarshal(rawBytes)
			if err != nil {
				return 0, err
			}
			aco.RawBytesSize += uint32(rawBytesSize)
			rawBytes = rawBytes[rawBytesSize:]
		}

		// Unmarshal INHERITED_OBJECT_TYPE
		if (aco.Flags.Value & flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT) == flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT {
			rawBytesSize, err = aco.InheritedObjectType.Unmarshal(rawBytes)
			if err != nil {
				return 0, err
			}
			aco.RawBytesSize += uint32(rawBytesSize)
			// rawBytes = rawBytes[rawBytesSize:]
		}
	}

	return int(aco.RawBytesSize), nil
}

// Marshal serializes the AccessControlObjectType struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the AccessControlObjectType.
func (aco *AccessControlObjectType) Marshal() ([]byte, error) {
	var marshalledData []byte

	bytesStream, err := aco.Flags.Marshal()
	if err != nil {
		return nil, err
	}
	marshalledData = append(marshalledData, bytesStream...)

	if (aco.Flags.Value & flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) == flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT {
		bytesStream, err = aco.ObjectType.Marshal()
		if err != nil {
			return nil, err
		}
		marshalledData = append(marshalledData, bytesStream...)
	}

	if (aco.Flags.Value & flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT) == flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT {
		bytesStream, err = aco.InheritedObjectType.Marshal()
		if err != nil {
			return nil, err
		}
		marshalledData = append(marshalledData, bytesStream...)
	}

	return marshalledData, nil
}

// Describe prints a human-readable representation of the AccessControlObjectType.
//
// Attributes:
//   - indent (int): The indentation level for the output.
//
// DescribeList returns the AccessControlObjectType description as a list of
// lines at indentation depth 0.
func (aco *AccessControlObjectType) DescribeList() []string {
	lines := []string{"<AccessControlObjectType>"}

	if aco.Flags.Value == (flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT | flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) {
		lines = append(lines,
			fmt.Sprintf(" │ \x1b[93mFlags\x1b[0m               : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)", aco.Flags.Value, aco.Flags.Name),
			fmt.Sprintf(" │ \x1b[93mObjectType\x1b[0m          : \x1b[96m%s\x1b[0m (\x1b[94m%s\x1b[0m)", aco.ObjectType.GUID.ToFormatD(), aco.ObjectType.GUID.LookupName()),
			fmt.Sprintf(" │ \x1b[93mInheritedObjectType\x1b[0m : \x1b[96m%s\x1b[0m (\x1b[94m%s\x1b[0m)", aco.InheritedObjectType.GUID.ToFormatD(), aco.InheritedObjectType.GUID.LookupName()),
		)
	} else if aco.Flags.Value == flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT {
		lines = append(lines,
			fmt.Sprintf(" │ \x1b[93mFlags\x1b[0m               : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)", aco.Flags.Value, aco.Flags.Name),
			fmt.Sprintf(" │ \x1b[93mInheritedObjectType\x1b[0m : \x1b[96m%s\x1b[0m (\x1b[94m%s\x1b[0m)", aco.InheritedObjectType.GUID.ToFormatD(), aco.InheritedObjectType.GUID.LookupName()),
		)
	} else if aco.Flags.Value == flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT {
		lines = append(lines,
			fmt.Sprintf(" │ \x1b[93mFlags\x1b[0m      : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)", aco.Flags.Value, aco.Flags.Name),
			fmt.Sprintf(" │ \x1b[93mObjectType\x1b[0m : \x1b[96m%s\x1b[0m (\x1b[94m%s\x1b[0m)", aco.ObjectType.GUID.ToFormatD(), aco.ObjectType.GUID.LookupName()),
		)
	} else if aco.Flags.Value == flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE {
		lines = append(lines,
			fmt.Sprintf(" │ \x1b[93mFlags\x1b[0m : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)", aco.Flags.Value, aco.Flags.Name),
		)
	} else {
		lines = append(lines,
			fmt.Sprintf(" │ \x1b[93mFlags\x1b[0m : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)", aco.Flags.Value, aco.Flags.Name),
		)
	}

	lines = append(lines, " └─")

	return lines
}

// DescribeWithCallback renders the AccessControlObjectType at the given
// indentation depth, routing each line to the provided fmt.Printf-like callback.
func (aco *AccessControlObjectType) DescribeWithCallback(indent int, printf describe.Printf) {
	describe.WithCallback(indent, aco.DescribeList(), printf)
}

func (aco *AccessControlObjectType) Describe(indent int) {
	aco.DescribeWithCallback(indent, fmt.Printf)
}
