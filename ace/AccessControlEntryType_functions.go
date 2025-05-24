package ace

// SetType sets the type of the Access Control Entry (ACE)
//
// The function takes a uint8 as an argument and assigns it to the Value field of the AccessControlEntryType.
func (acetype *AccessControlEntryType) SetType(typ uint8) {
	acetype.Value = typ
}

// GetType returns the type of the Access Control Entry (ACE)
//
// The function returns the value of the AccessControlEntryType as a uint8.
func (acetype *AccessControlEntryType) GetType() uint8 {
	return acetype.Value
}
