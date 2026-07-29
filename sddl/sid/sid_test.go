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

// msdtypSidTokens is the complete sid-token list from MS-DTYP 2.5.1.1. Every one
// of these MUST resolve; "AC", "UD" and "WR" were previously absent.
var msdtypSidTokens = []string{
	"DA", "DG", "DU", "ED", "DD", "DC", "BA", "BG", "BU", "LA", "LG", "AO", "BO",
	"PO", "SO", "AU", "PS", "CO", "CG", "SY", "PU", "WD", "RE", "IU", "NU", "SU",
	"RC", "WR", "AN", "SA", "CA", "RS", "EA", "PA", "RU", "LS", "NS", "RD", "NO",
	"MU", "LU", "IS", "CY", "OW", "ER", "RO", "CD", "AC", "RA", "ES", "MS", "UD",
	"HA", "CN", "AA", "RM", "LW", "ME", "MP", "HI", "SI",
}

// TestSDDLAliases_MSDTYPCoverage checks that every alias in the MS-DTYP
// sid-token table resolves to a SID.
func TestSDDLAliases_MSDTYPCoverage(t *testing.T) {
	for _, alias := range msdtypSidTokens {
		if got, ok := SDDLToSID[alias]; !ok || got == "" {
			t.Errorf("SDDLToSID[%q] missing; MS-DTYP 2.5.1.1 defines it as a sid-token", alias)
		}
	}
}

// TestSDDLAliases_WindowsExtras pins the aliases Windows resolves that the
// MS-DTYP sid-token table does not list. Values were read from the alias table
// in sechost.dll (Windows Server 2025), .data RVA 0x99f30.
func TestSDDLAliases_WindowsExtras(t *testing.T) {
	want := map[string]string{
		// Documented by MS-DTYP but previously missing here.
		"AC": "S-1-15-2-1",
		"UD": "S-1-5-84-0-0-0-0-0",
		"WR": "S-1-5-33",
		// Not in the MS-DTYP sid-token table.
		"AS": "S-1-18-1",
		"SS": "S-1-18-2",
		"HO": "S-1-5-32-584",
		"SH": "S-1-5-32-585",
		"AP": "S-1-5-21-0-0-0-525",
		"KA": "S-1-5-21-0-0-0-526",
		"EK": "S-1-5-21-0-0-0-527",
	}
	for alias, wantSID := range want {
		got, ok := SDDLToSID[alias]
		if !ok {
			t.Errorf("SDDLToSID[%q] missing, want %q", alias, wantSID)
			continue
		}
		if got != wantSID {
			t.Errorf("SDDLToSID[%q] = %q, want %q", alias, got, wantSID)
		}
		if back := SIDToSDDL[wantSID]; back != alias {
			t.Errorf("SIDToSDDL[%q] = %q, want %q", wantSID, back, alias)
		}
	}
}

// TestSDDLAliases_NoDuplicateSIDs guards the derived reverse map: two aliases
// sharing a SID would make SIDToSDDL depend on map iteration order.
func TestSDDLAliases_NoDuplicateSIDs(t *testing.T) {
	seen := make(map[string]string, len(SDDLToSID))
	for alias, sidStr := range SDDLToSID {
		if other, dup := seen[sidStr]; dup {
			t.Errorf("aliases %q and %q both map to %q; SIDToSDDL[%q] is nondeterministic",
				other, alias, sidStr, sidStr)
		}
		seen[sidStr] = alias
	}
}
