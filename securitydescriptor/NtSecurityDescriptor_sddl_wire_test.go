package securitydescriptor

import (
	"encoding/binary"
	"testing"
)

// TestFromSDDLString_MarshalWireControl verifies that a security descriptor
// parsed from SDDL marshals to a Control word matching the Windows wire format,
// so that it is accepted by NT servers (e.g. RPC calls taking self-relative
// security descriptors). Regression test for issue #92.
func TestFromSDDLString_MarshalWireControl(t *testing.T) {
	ntsd := NtSecurityDescriptor{}
	if _, err := ntsd.FromSDDLString("O:SYG:SYD:(A;;FA;;;BA)(A;;FA;;;SY)"); err != nil {
		t.Fatalf("FromSDDLString() error = %v", err)
	}
	buf, err := ntsd.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	ctrl := binary.LittleEndian.Uint16(buf[2:4])
	// SE_SELF_RELATIVE (0x8000) | SE_DACL_PRESENT (0x0004)
	const want = 0x8004
	if ctrl != want {
		t.Errorf("marshaled control word = 0x%04x, want 0x%04x (SE_SELF_RELATIVE|SE_DACL_PRESENT)", ctrl, want)
	}
}
