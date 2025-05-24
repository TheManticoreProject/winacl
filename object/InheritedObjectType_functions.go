package object

import "github.com/TheManticoreProject/winacl/guid"

// Equal returns true if the InheritedObjectType is equal to the other InheritedObjectType.
func (inheritedObjType *InheritedObjectType) Equal(other *InheritedObjectType) bool {
	return inheritedObjType.GUID.Equal(&other.GUID)
}

// GetName returns the name of the InheritedObjectType.
func (inheritedObjType *InheritedObjectType) GetName() string {
	return inheritedObjType.Name
}

// SetName sets the name of the InheritedObjectType.
func (inheritedObjType *InheritedObjectType) SetName(name string) {
	inheritedObjType.Name = name
}

// GetGUID returns the GUID of the InheritedObjectType.
func (inheritedObjType *InheritedObjectType) GetGUID() guid.GUID {
	return inheritedObjType.GUID
}

// SetGUID sets the GUID of the InheritedObjectType.
func (inheritedObjType *InheritedObjectType) SetGUID(guid guid.GUID) {
	inheritedObjType.GUID = guid
}
