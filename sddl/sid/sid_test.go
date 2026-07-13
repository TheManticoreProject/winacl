package sid

import (
	"testing"
)

func TestSid(t *testing.T) {

}

// TestSDDLAlias_RO is a regression test for the SDDL alias "RO" mapping to the
// wrong RID. Per the Microsoft SID Strings reference, "RO" is
// SDDL_ENTERPRISE_RO_DCs (Enterprise Read-Only Domain Controllers),
// DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS = 498. It was
// previously mapped to 521 (the plain Read-Only Domain Controllers group,
// which has no SDDL alias).
func TestSDDLAlias_RO(t *testing.T) {
	const want = "S-1-5-21-0-0-0-498"

	if got := SDDLToSID["RO"]; got != want {
		t.Errorf("SDDLToSID[\"RO\"] = %q, want %q", got, want)
	}

	// The reverse mapping is derived from SDDLToSID, so it must resolve the
	// correct SID back to "RO".
	if got := SIDToSDDL[want]; got != "RO" {
		t.Errorf("SIDToSDDL[%q] = %q, want \"RO\"", want, got)
	}

	// RID 521 must no longer be aliased to "RO".
	if got, ok := SIDToSDDL["S-1-5-21-0-0-0-521"]; ok && got == "RO" {
		t.Errorf("S-1-5-21-0-0-0-521 must not map to \"RO\" (it is the non-aliased Read-Only Domain Controllers group)")
	}
}
