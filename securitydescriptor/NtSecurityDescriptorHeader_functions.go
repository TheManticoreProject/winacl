package securitydescriptor

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
