package header_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/securitydescriptor/header"
)

func TestNtSecurityDescriptorHeader_GetSetRevision(t *testing.T) {
	header := &header.NtSecurityDescriptorHeader{}

	// Test setting and getting revision
	testRevision := uint8(1)
	header.SetRevision(testRevision)

	if got := header.GetRevision(); got != testRevision {
		t.Errorf("GetRevision() = %v, want %v", got, testRevision)
	}
}

func TestNtSecurityDescriptorHeader_GetSetSbz1(t *testing.T) {
	header := &header.NtSecurityDescriptorHeader{}

	// Test setting and getting Sbz1
	testSbz1 := uint8(2)
	header.SetSbz1(testSbz1)

	if got := header.GetSbz1(); got != testSbz1 {
		t.Errorf("GetSbz1() = %v, want %v", got, testSbz1)
	}
}

func TestNtSecurityDescriptorHeader_Equal(t *testing.T) {
	header1 := &header.NtSecurityDescriptorHeader{}
	header2 := &header.NtSecurityDescriptorHeader{}

	// Test when both headers are empty/default
	if !header1.Equal(header2) {
		t.Error("Equal() returned false for identical empty headers")
	}

	// Test when headers have same values
	header1.SetRevision(1)
	header1.SetSbz1(2)
	header2.SetRevision(1)
	header2.SetSbz1(2)

	if !header1.Equal(header2) {
		t.Error("Equal() returned false for identical populated headers")
	}

	// Test when headers have different values
	header2.SetRevision(3)
	if header1.Equal(header2) {
		t.Error("Equal() returned true for headers with different revisions")
	}

	// Reset revision and change Sbz1
	header2.SetRevision(1)
	header2.SetSbz1(4)
	if header1.Equal(header2) {
		t.Error("Equal() returned true for headers with different Sbz1 values")
	}

	// Test with nil
	if header1.Equal(nil) {
		t.Error("Equal() returned true when comparing with nil")
	}
}
