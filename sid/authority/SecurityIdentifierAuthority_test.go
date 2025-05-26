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
