package aceflags

import (
	ntsd_aceflags "github.com/TheManticoreProject/winacl/ace/aceflags"
)

// SDDL ACE flag abbreviations to binary flag values.
// Source: https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings

var SDDLToACEFlag = map[string]uint8{
	"CI": ntsd_aceflags.ACE_FLAG_CONTAINER_INHERIT,
	"OI": ntsd_aceflags.ACE_FLAG_OBJECT_INHERIT,
	"NP": ntsd_aceflags.ACE_FLAG_NO_PROPAGATE_INHERIT,
	"IO": ntsd_aceflags.ACE_FLAG_INHERIT_ONLY,
	"ID": ntsd_aceflags.ACE_FLAG_INHERITED,
	"SA": ntsd_aceflags.ACE_FLAG_SUCCESSFUL_ACCESS,
	"FA": ntsd_aceflags.ACE_FLAG_FAILED_ACCESS,
}

var ACEFlagToSDDL map[uint8]string

func init() {
	ACEFlagToSDDL = make(map[uint8]string, len(SDDLToACEFlag))
	for sddl, flag := range SDDLToACEFlag {
		ACEFlagToSDDL[flag] = sddl
	}
}
