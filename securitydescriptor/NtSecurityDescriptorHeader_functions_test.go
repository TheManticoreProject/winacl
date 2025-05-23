package securitydescriptor_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

func TestNtSecurityDescriptorHeader_GetSetRevision(t *testing.T) {
	header := &securitydescriptor.NtSecurityDescriptorHeader{}

	// Test setting and getting revision
	testRevision := uint8(1)
	header.SetRevision(testRevision)

	if got := header.GetRevision(); got != testRevision {
		t.Errorf("GetRevision() = %v, want %v", got, testRevision)
	}
}

func TestNtSecurityDescriptorHeader_GetSetSbz1(t *testing.T) {
	header := &securitydescriptor.NtSecurityDescriptorHeader{}

	// Test setting and getting Sbz1
	testSbz1 := uint8(2)
	header.SetSbz1(testSbz1)

	if got := header.GetSbz1(); got != testSbz1 {
		t.Errorf("GetSbz1() = %v, want %v", got, testSbz1)
	}
}
