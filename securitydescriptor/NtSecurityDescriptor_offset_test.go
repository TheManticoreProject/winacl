package securitydescriptor_test

import (
	"encoding/binary"
	"testing"

	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

// TestNtSecurityDescriptor_Unmarshal_OffsetInsideHeader verifies that a
// component offset pointing inside the 20-byte header is rejected instead of
// being parsed as garbage.
func TestNtSecurityDescriptor_Unmarshal_OffsetInsideHeader(t *testing.T) {
	ntsd := securitydescriptor.NewSecurityDescriptor()
	ntsd.Owner.SID.FromString("S-1-5-32-544")

	data, err := ntsd.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Sanity check: the unmodified descriptor parses cleanly.
	if _, err := (&securitydescriptor.NtSecurityDescriptor{}).Unmarshal(data); err != nil {
		t.Fatalf("Unmarshal() of valid descriptor error = %v", err)
	}

	// OffsetOwner is the little-endian uint32 at bytes 4..8. Point it inside the
	// header region (offset 4) to simulate a malformed/crafted descriptor.
	binary.LittleEndian.PutUint32(data[4:8], 4)

	parsed := &securitydescriptor.NtSecurityDescriptor{}
	if _, err := parsed.Unmarshal(data); err == nil {
		t.Error("Unmarshal() = nil error, want error for an owner offset inside the header")
	}
}
