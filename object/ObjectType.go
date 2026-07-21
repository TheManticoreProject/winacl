package object

import (
	"fmt"

	"github.com/TheManticoreProject/winacl/guid"
	"github.com/TheManticoreProject/winacl/utils/describe"
)

// ObjectType represents a type of object with an associated GUID.
// It contains the object's name, its GUID for identification,
// and internal fields for storing raw bytes and their size.
type ObjectType struct {
	// Name is the human-readable name of the object type.
	Name string

	// GUID is the globally unique identifier for the object type.
	GUID guid.GUID

	// RawBytes stores the raw byte representation of the object type.
	// This is useful for low-level operations or serialization.
	RawBytes []byte

	// RawBytesSize stores the size of the RawBytes field in bytes.
	RawBytesSize uint32
}

// Unmarshal initializes the ObjectType from the given raw byte slice.
// It expects the RawBytes to be at least 16 bytes long, as that is the size needed to store the GUID.
// It also sets the RawBytes and RawBytesSize fields.
func (objType *ObjectType) Unmarshal(rawBytes []byte) (int, error) {
	objType.RawBytes = rawBytes
	objType.RawBytesSize = 0

	rawBytesSize, err := objType.GUID.Unmarshal(rawBytes)
	if err != nil {
		return 0, err
	}
	objType.RawBytesSize += uint32(rawBytesSize)

	return int(objType.RawBytesSize), nil
}

// Marshal returns the raw byte representation of the ObjectType.
// It returns the GUID as a byte slice.
func (objType *ObjectType) Marshal() ([]byte, error) {
	bytesStream, err := objType.GUID.Marshal()
	if err != nil {
		return nil, err
	}
	objType.RawBytesSize = uint32(len(bytesStream))
	return bytesStream, nil
}

// Describe prints a formatted representation of the ObjectType instance,
// including its GUID, to the standard output. The output is indented
// based on the provided indent level for better readability.
// DescribeList returns the ObjectType description as a list of lines at
// indentation depth 0.
func (objType *ObjectType) DescribeList() []string {
	return []string{
		"<ObjectType>",
		fmt.Sprintf(" │ \x1b[93mGUID\x1b[0m : \x1b[96m%s\x1b[0m", objType.GUID.ToFormatD()),
		" └─",
	}
}

// DescribeWithCallback renders the ObjectType at the given indentation depth,
// routing each line to the provided fmt.Printf-like callback.
func (objType *ObjectType) DescribeWithCallback(indent int, printf describe.Printf) {
	describe.WithCallback(indent, objType.DescribeList(), printf)
}

func (objType *ObjectType) Describe(indent int) {
	objType.DescribeWithCallback(indent, describe.Printfln)
}
