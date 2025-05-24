package acl

const (
	ACL_REVISION    = 0x02
	ACL_REVISION_DS = 0x04
)

// AccessControlListRevision represents the revision of an access control list.
type AccessControlListRevision struct {
	Value uint8
}

// Unmarshal parses the AccessControlListRevision struct from a byte slice.
//
// Parameters:
//   - rawBytes ([]byte): The byte slice to parse.
func (aclrev *AccessControlListRevision) Unmarshal(marshalledData []byte) (int, error) {
	aclrev.Value = uint8(marshalledData[0])

	return 1, nil
}

// Marshal serializes the AccessControlListRevision struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the ACL revision.
func (aclrev *AccessControlListRevision) Marshal() ([]byte, error) {
	var serializedData []byte

	serializedData = append(serializedData, aclrev.Value)

	return serializedData, nil
}

// String returns the string representation of the AccessControlListRevision struct.
//
// Returns:
//   - string: The string representation of the AccessControlListRevision.
func (aclrev *AccessControlListRevision) String() string {
	if aclrev.Value == ACL_REVISION_DS {
		return "ACL_REVISION_DS"
	} else if aclrev.Value == ACL_REVISION {
		return "ACL_REVISION"
	} else {
		return "?"
	}
}
