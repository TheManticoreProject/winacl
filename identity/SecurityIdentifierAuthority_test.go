package identity

import (
	"testing"
)

func Test_SIDAuthorityValueToName(t *testing.T) {
	values := []uint64{
		SID_AUTHORITY_NULL,
		SID_AUTHORITY_WORLD,
		SID_AUTHORITY_LOCAL,
		SID_AUTHORITY_CREATOR,
		SID_AUTHORITY_NON_UNIQUE,
		SID_AUTHORITY_SECURITY_NT,
		SID_AUTHORITY_SECURITY_APP_PACKAGE,
		SID_AUTHORITY_SECURITY_MANDATORY_LABEL,
		SID_AUTHORITY_SECURITY_SCOPED_POLICY_ID,
		SID_AUTHORITY_SECURITY_AUTHENTICATION,
	}
	for _, sia := range values {
		if _, exists := SIDAuthorityNames[sia]; !exists {
			t.Errorf("SID Authority Value %012x not found in SIDAuthorityNames", sia)
		}
	}
}
