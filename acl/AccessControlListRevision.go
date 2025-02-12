package acl

const (
	ACL_REVISION    = 0x02
	ACL_REVISION_DS = 0x04
)

// AccessControlListRevision represents the revision of an access control list.
type AccessControlListRevision struct {
	Value uint8
}

// Parse parses the AccessControlListRevision struct from a byte slice.
//
// Parameters:
//   - rawBytes ([]byte): The byte slice to parse.
func (aclrev *AccessControlListRevision) Parse(rawBytes []byte) {
	aclrev.Value = uint8(rawBytes[0])
}

// ToBytes serializes the AccessControlListRevision struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the ACL revision.
func (aclrev *AccessControlListRevision) ToBytes() []byte {
	var serializedData []byte
	serializedData = append(serializedData, aclrev.Value)
	return serializedData
}

// String returns the string representation of the AccessControlListRevision struct.
func (aclrev *AccessControlListRevision) String() string {
	if aclrev.Value == ACL_REVISION_DS {
		return "ACL_REVISION_DS"
	} else if aclrev.Value == ACL_REVISION {
		return "ACL_REVISION"
	} else {
		return "?"
	}
}
