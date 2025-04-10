package object

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/winacl/guid"
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

// Parse initializes the ObjectType from the given raw byte slice.
// It expects the RawBytes to be at least 16 bytes long, as that is the size needed to store the GUID.
// It also sets the RawBytes and RawBytesSize fields.
func (objType *ObjectType) Parse(RawBytes []byte) {
	objType.RawBytes = RawBytes
	objType.RawBytesSize = 16
	objType.GUID.FromRawBytes(RawBytes)
}

// ToBytes returns the raw byte representation of the ObjectType.
// It returns the GUID as a byte slice.
func (objType *ObjectType) ToBytes() []byte {
	return objType.GUID.ToBytes()
}

// Describe prints a formatted representation of the ObjectType instance,
// including its GUID, to the standard output. The output is indented
// based on the provided indent level for better readability.
func (objType *ObjectType) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<ObjectType>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mGUID\x1b[0m : \x1b[96m%s\x1b[0m\n", indentPrompt, objType.GUID.ToFormatD())
	fmt.Printf("%s └─\n", indentPrompt)
}
