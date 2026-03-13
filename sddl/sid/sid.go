package sid

// SDDL SID abbreviation to full SID string mappings.
// Source: https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings

var SDDLToSID = map[string]string{
	// Well-known SIDs
	"WD": "S-1-1-0",  // Everyone
	"CO": "S-1-3-0",  // Creator Owner
	"CG": "S-1-3-1",  // Creator Group
	"OW": "S-1-3-4",  // Owner Rights
	"NU": "S-1-5-2",  // Network
	"IU": "S-1-5-4",  // Interactive
	"SU": "S-1-5-6",  // Service
	"AN": "S-1-5-7",  // Anonymous
	"ED": "S-1-5-9",  // Enterprise Domain Controllers
	"PS": "S-1-5-10", // Principal Self
	"AU": "S-1-5-11", // Authenticated Users
	"RC": "S-1-5-12", // Restricted Code
	"SY": "S-1-5-18", // Local System
	"LS": "S-1-5-19", // Local Service
	"NS": "S-1-5-20", // Network Service

	// BUILTIN groups
	"BA": "S-1-5-32-544", // BUILTIN\Administrators
	"BU": "S-1-5-32-545", // BUILTIN\Users
	"BG": "S-1-5-32-546", // BUILTIN\Guests
	"PU": "S-1-5-32-547", // BUILTIN\Power Users
	"AO": "S-1-5-32-548", // BUILTIN\Account Operators
	"SO": "S-1-5-32-549", // BUILTIN\Server Operators
	"PO": "S-1-5-32-550", // BUILTIN\Print Operators
	"BO": "S-1-5-32-551", // BUILTIN\Backup Operators
	"RE": "S-1-5-32-552", // BUILTIN\Replicators
	"RU": "S-1-5-32-554", // BUILTIN\Pre-Windows 2000 Compatible Access
	"RD": "S-1-5-32-555", // BUILTIN\Remote Desktop Users
	"NO": "S-1-5-32-556", // BUILTIN\Network Configuration Operators
	"MU": "S-1-5-32-558", // BUILTIN\Performance Monitor Users
	"LU": "S-1-5-32-559", // BUILTIN\Performance Log Users
	"IS": "S-1-5-32-568", // BUILTIN\IIS_IUSRS
	"CY": "S-1-5-32-569", // BUILTIN\Cryptographic Operators
	"ER": "S-1-5-32-573", // BUILTIN\Event Log Readers
	"CD": "S-1-5-32-574", // BUILTIN\Certificate Service DCOM Access
	"RA": "S-1-5-32-575", // BUILTIN\RDS Remote Access Servers
	"ES": "S-1-5-32-576", // BUILTIN\RDS Endpoint Servers
	"MS": "S-1-5-32-577", // BUILTIN\RDS Management Servers
	"HA": "S-1-5-32-578", // BUILTIN\Hyper-V Administrators
	"AA": "S-1-5-32-579", // BUILTIN\Access Control Assistance Operators
	"RM": "S-1-5-32-580", // BUILTIN\Remote Management Users

	// Domain-relative SIDs (using placeholder domain 0-0-0)
	"LA": "S-1-5-21-0-0-0-500", // Domain Administrator Account
	"LG": "S-1-5-21-0-0-0-501", // Domain Guest Account
	"DA": "S-1-5-21-0-0-0-512", // Domain Admins
	"DU": "S-1-5-21-0-0-0-513", // Domain Users
	"DG": "S-1-5-21-0-0-0-514", // Domain Guests
	"DC": "S-1-5-21-0-0-0-515", // Domain Computers
	"DD": "S-1-5-21-0-0-0-516", // Domain Controllers
	"CA": "S-1-5-21-0-0-0-517", // Cert Publishers
	"SA": "S-1-5-21-0-0-0-518", // Schema Admins
	"EA": "S-1-5-21-0-0-0-519", // Enterprise Admins
	"PA": "S-1-5-21-0-0-0-520", // Group Policy Creator Owners
	"RO": "S-1-5-21-0-0-0-521", // Read-Only Domain Controllers
	"CN": "S-1-5-21-0-0-0-522", // Cloneable Domain Controllers
	"RS": "S-1-5-21-0-0-0-553", // RAS Servers Group

	// Mandatory integrity levels
	"LW": "S-1-16-4096",  // Low Integrity Level
	"ME": "S-1-16-8192",  // Medium Integrity Level
	"MP": "S-1-16-8448",  // Medium Plus Integrity Level
	"HI": "S-1-16-12288", // High Integrity Level
	"SI": "S-1-16-16384", // System Integrity Level
}

// SIDToSDDL is the reverse mapping from full SID strings to SDDL abbreviations.
var SIDToSDDL map[string]string

func init() {
	SIDToSDDL = make(map[string]string, len(SDDLToSID))
	for abbrev, sidStr := range SDDLToSID {
		SIDToSDDL[sidStr] = abbrev
	}
}
