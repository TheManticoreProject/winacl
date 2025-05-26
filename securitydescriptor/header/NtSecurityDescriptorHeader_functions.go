package header

// GetRevision returns the Revision field value.
func (ntsd *NtSecurityDescriptorHeader) GetRevision() uint8 {
	return ntsd.Revision
}

// SetRevision sets the Revision field value.
func (ntsd *NtSecurityDescriptorHeader) SetRevision(revision uint8) {
	ntsd.Revision = revision
}

// GetSbz1 returns the Sbz1 field value.
func (ntsd *NtSecurityDescriptorHeader) GetSbz1() uint8 {
	return ntsd.Sbz1
}

// SetSbz1 sets the Sbz1 field value.
func (ntsd *NtSecurityDescriptorHeader) SetSbz1(sbz1 uint8) {
	ntsd.Sbz1 = sbz1
}

// Equal compares two NtSecurityDescriptorHeader instances for equality.
//
// Parameters:
//   - other (*NtSecurityDescriptorHeader): The NtSecurityDescriptorHeader to compare with.
//
// Returns:
//   - bool: True if the NtSecurityDescriptorHeaders are equal, false otherwise.
func (ntsdh *NtSecurityDescriptorHeader) Equal(other *NtSecurityDescriptorHeader) bool {
	if ntsdh == nil || other == nil {
		return ntsdh == other
	}

	if ntsdh.Revision != other.Revision {
		return false
	}

	if ntsdh.Sbz1 != other.Sbz1 {
		return false
	}

	if !ntsdh.Control.Equal(&other.Control) {
		return false
	}

	if ntsdh.OffsetOwner != other.OffsetOwner {
		return false
	}

	if ntsdh.OffsetGroup != other.OffsetGroup {
		return false
	}

	if ntsdh.OffsetSacl != other.OffsetSacl {
		return false
	}

	if ntsdh.OffsetDacl != other.OffsetDacl {
		return false
	}

	return true
}
