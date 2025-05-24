package object

// IsObjectTypePresent returns true if the ObjectType flag is set.
func (acotype *AccessControlObjectTypeFlags) IsObjectTypePresent() bool {
	return (acotype.Value & ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) == ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT
}

// IsInheritedObjectTypePresent returns true if the InheritedObjectType flag is set.
func (acotype *AccessControlObjectTypeFlags) IsInheritedObjectTypePresent() bool {
	return (acotype.Value & ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT) == ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT
}

// IsNone returns true if no flags are set.
func (acotype *AccessControlObjectTypeFlags) IsNone() bool {
	return acotype.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE
}

// SetObjectTypePresent sets the ObjectType flag.
func (acotype *AccessControlObjectTypeFlags) SetObjectTypePresent() {
	acotype.Value |= ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT
}

// SetInheritedObjectTypePresent sets the InheritedObjectType flag.
func (acotype *AccessControlObjectTypeFlags) SetInheritedObjectTypePresent() {
	acotype.Value |= ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT
}

// ClearObjectTypePresent clears the ObjectType flag.
func (acotype *AccessControlObjectTypeFlags) ClearObjectTypePresent() {
	acotype.Value &^= ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT
}

// ClearInheritedObjectTypePresent clears the InheritedObjectType flag.
func (acotype *AccessControlObjectTypeFlags) ClearInheritedObjectTypePresent() {
	acotype.Value &^= ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT
}

// Clear clears all flags.
func (acotype *AccessControlObjectTypeFlags) Clear() {
	acotype.Value = ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE
}
