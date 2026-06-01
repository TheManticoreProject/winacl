package ace_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/acetype"
)

// TestACE_Marshal_OversizedApplicationData verifies that marshalling an ACE
// whose body would exceed the uint16 Header.Size field returns an error instead
// of silently wrapping into a tiny, corrupt size.
func TestACE_Marshal_OversizedApplicationData(t *testing.T) {
	a := ace.AccessControlEntry{}
	a.Header.Type.Value = acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK
	a.Mask.SetRights([]uint32{0x00000001})
	a.Identity.SID.FromString("S-1-1-0")
	a.ApplicationData = make([]byte, 0x10000) // 65536 bytes: body + header > 65535

	if _, err := a.Marshal(); err == nil {
		t.Error("Marshal() = nil error, want error for ACE exceeding the uint16 Header.Size maximum")
	}
}

// TestACE_Marshal_NormalSizeOK verifies the overflow guard does not affect a
// normally sized ACE.
func TestACE_Marshal_NormalSizeOK(t *testing.T) {
	a := ace.AccessControlEntry{}
	a.Header.Type.Value = acetype.ACE_TYPE_ACCESS_ALLOWED
	a.Mask.SetRights([]uint32{0x00000001})
	a.Identity.SID.FromString("S-1-1-0")

	if _, err := a.Marshal(); err != nil {
		t.Fatalf("Marshal() of a normal ACE error = %v", err)
	}
}
