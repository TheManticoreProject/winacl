package authority_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/sid/authority"
)

func Test_SIDAuthorityValueToName(t *testing.T) {
	values := []uint64{
		authority.SID_AUTHORITY_NULL,
		authority.SID_AUTHORITY_WORLD,
		authority.SID_AUTHORITY_LOCAL,
		authority.SID_AUTHORITY_CREATOR,
		authority.SID_AUTHORITY_NON_UNIQUE,
		authority.SID_AUTHORITY_SECURITY_NT,
		authority.SID_AUTHORITY_SECURITY_APP_PACKAGE,
		authority.SID_AUTHORITY_SECURITY_MANDATORY_LABEL,
		authority.SID_AUTHORITY_SECURITY_SCOPED_POLICY_ID,
		authority.SID_AUTHORITY_SECURITY_AUTHENTICATION,
	}
	for _, sia := range values {
		if _, exists := authority.SIDAuthorityNames[sia]; !exists {
			t.Errorf("SID Authority Value %012x not found in SIDAuthorityNames", sia)
		}
	}
}

// Test_SecurityIdentifierAuthority_Unmarshal_TruncatedReturnsError asserts that
// Unmarshal returns a parse error instead of panicking when fewer than 6 bytes
// are provided. Regression test for issue #30.
func Test_SecurityIdentifierAuthority_Unmarshal_TruncatedReturnsError(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 4, 5} {
		buf := make([]byte, n)
		var a authority.SecurityIdentifierAuthority
		_, err := a.Unmarshal(buf)
		if err == nil {
			t.Errorf("Unmarshal(%d bytes) expected error, got nil", n)
		}
	}
}
