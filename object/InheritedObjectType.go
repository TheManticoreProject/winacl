package object

import (
	"fmt"

	"github.com/TheManticoreProject/winacl/guid"
	"github.com/TheManticoreProject/winacl/utils/describe"
)

// InheritedObjectType represents a type of object that inherits
// properties or permissions from a parent object in a security
// descriptor context.
type InheritedObjectType struct {
	// Name represents the name of the inherited object type.
	Name string

	// GUID is the globally unique identifier associated with this
	// inherited object type, used for distinguishing it within the
	// security descriptor.
	GUID guid.GUID

	// Internal fields
	// RawBytes holds the raw byte representation of the object type,
	// allowing for low-level access to its binary structure.
	RawBytes []byte

	// RawBytesSize stores the size of the RawBytes slice, which can
	// be useful for parsing and validating the data structure.
	RawBytesSize uint32
}

// Unmarshal takes a byte slice (RawBytes) as input, which represents the raw data
// for an InheritedObjectType instance. It populates the instance's fields,
// specifically setting the RawBytes and RawBytesSize, and parsing the GUID
// from the provided raw data.
func (inheritedObjType *InheritedObjectType) Unmarshal(rawBytes []byte) (int, error) {
	inheritedObjType.RawBytes = rawBytes
	inheritedObjType.RawBytesSize = 0

	rawBytesSize, err := inheritedObjType.GUID.Unmarshal(rawBytes)
	if err != nil {
		return 0, err
	}
	inheritedObjType.RawBytesSize += uint32(rawBytesSize)

	return int(inheritedObjType.RawBytesSize), nil
}

// Marshal returns the raw byte representation of the InheritedObjectType.
// It returns the GUID as a byte slice.
func (inheritedObjType *InheritedObjectType) Marshal() ([]byte, error) {
	bytesStream, err := inheritedObjType.GUID.Marshal()
	if err != nil {
		return nil, err
	}
	inheritedObjType.RawBytesSize = uint32(len(bytesStream))
	return bytesStream, nil
}

// Describe prints a formatted representation of the InheritedObjectType instance,
// including its GUID, to the standard output. The output is indented
// based on the provided indent level for better readability.
// DescribeList returns the InheritedObjectType description as a list of lines at
// indentation depth 0.
func (inheritedObjType *InheritedObjectType) DescribeList() []string {
	return []string{
		"<InheritedObjectType>",
		fmt.Sprintf(" │ \x1b[93mGUID\x1b[0m : \x1b[96m%s\x1b[0m", inheritedObjType.GUID.ToFormatD()),
		" └─",
	}
}

// DescribeWithCallback renders the InheritedObjectType at the given indentation
// depth, routing each line to the provided fmt.Printf-like callback.
func (inheritedObjType *InheritedObjectType) DescribeWithCallback(indent int, printf describe.Printf) {
	describe.WithCallback(indent, inheritedObjType.DescribeList(), printf)
}

func (inheritedObjType *InheritedObjectType) Describe(indent int) {
	inheritedObjType.DescribeWithCallback(indent, describe.Printfln)
}
