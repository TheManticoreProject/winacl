package rights

import (
	ntsd_rights "github.com/TheManticoreProject/winacl/rights"
)

// SDDL rights abbreviations to binary access mask values.
// Source: https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings

var SDDLToRight = map[string]uint32{
	// Generic rights
	"GA": ntsd_rights.RIGHT_GENERIC_ALL,
	"GR": ntsd_rights.RIGHT_GENERIC_READ,
	"GW": ntsd_rights.RIGHT_GENERIC_WRITE,
	"GX": ntsd_rights.RIGHT_GENERIC_EXECUTE,

	// Standard rights
	"RC": ntsd_rights.RIGHT_READ_CONTROL,
	"SD": ntsd_rights.RIGHT_DELETE,
	"WD": ntsd_rights.RIGHT_WRITE_DAC,
	"WO": ntsd_rights.RIGHT_WRITE_OWNER,

	// Directory service rights
	"RP": ntsd_rights.RIGHT_DS_READ_PROPERTY,
	"WP": ntsd_rights.RIGHT_DS_WRITE_PROPERTY,
	"CC": ntsd_rights.RIGHT_DS_CREATE_CHILD,
	"DC": ntsd_rights.RIGHT_DS_DELETE_CHILD,
	"LC": ntsd_rights.RIGHT_DS_LIST_CONTENTS,
	"SW": ntsd_rights.RIGHT_DS_WRITE_PROPERTY_EXTENDED,
	"LO": ntsd_rights.RIGHT_DS_LIST_OBJECT,
	"DT": ntsd_rights.RIGHT_DS_DELETE_TREE,
	"CR": ntsd_rights.RIGHT_DS_CONTROL_ACCESS,

	// File rights
	"FA": 0x001F01FF, // FILE_ALL_ACCESS
	"FR": 0x00120089, // FILE_GENERIC_READ
	"FW": 0x00120116, // FILE_GENERIC_WRITE
	"FX": 0x001200A0, // FILE_GENERIC_EXECUTE

	// Registry rights
	"KA": 0x000F003F, // KEY_ALL_ACCESS
	"KR": 0x00020019, // KEY_READ
	"KW": 0x00020006, // KEY_WRITE
	"KX": 0x00020019, // KEY_EXECUTE

	// Mandatory label rights
	"NR": 0x00000001, // SYSTEM_MANDATORY_LABEL_NO_READ_UP
	"NW": 0x00000002, // SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
	"NX": 0x00000004, // SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
}

var RightToSDDL map[uint32]string

func init() {
	RightToSDDL = make(map[uint32]string, len(SDDLToRight))
	for sddl, right := range SDDLToRight {
		RightToSDDL[right] = sddl
	}
}
