package object

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/winacl/guid"
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

// Parse takes a byte slice (RawBytes) as input, which represents the raw data
// for an InheritedObjectType instance. It populates the instance's fields,
// specifically setting the RawBytes and RawBytesSize, and parsing the GUID
// from the provided raw data.
func (inheritedObjType *InheritedObjectType) Parse(RawBytes []byte) {
	inheritedObjType.RawBytes = RawBytes
	inheritedObjType.RawBytesSize = 16
	inheritedObjType.GUID.FromRawBytes(RawBytes)
}

// ToBytes returns the raw byte representation of the ObjectType.
// It returns the GUID as a byte slice.
func (inheritedObjType *InheritedObjectType) ToBytes() []byte {
	return inheritedObjType.GUID.ToBytes()
}

// Describe prints a formatted representation of the InheritedObjectType instance,
// including its GUID, to the standard output. The output is indented
// based on the provided indent level for better readability.
func (inheritedObjType *InheritedObjectType) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<InheritedObjectType>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mGUID\x1b[0m : \x1b[96m%s\x1b[0m\n", indentPrompt, inheritedObjType.GUID.ToFormatD())
	fmt.Printf("%s └─\n", indentPrompt)
}
