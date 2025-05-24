package object

import "github.com/TheManticoreProject/winacl/guid"

// Equal returns true if the ObjectType is equal to the other ObjectType.
func (objType *ObjectType) Equal(other *ObjectType) bool {
	return objType.GUID.Equal(&other.GUID)
}

// GetName returns the name of the ObjectType.
func (objType *ObjectType) GetName() string {
	return objType.Name
}

// SetName sets the name of the ObjectType.
func (objType *ObjectType) SetName(name string) {
	objType.Name = name
}

// GetGUID returns the GUID of the ObjectType.
func (objType *ObjectType) GetGUID() guid.GUID {
	return objType.GUID
}

// SetGUID sets the GUID of the ObjectType.
func (objType *ObjectType) SetGUID(guid guid.GUID) {
	objType.GUID = guid
}
