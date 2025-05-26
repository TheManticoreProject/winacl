package acetype

import (
	ntsd_acetype "github.com/TheManticoreProject/winacl/ace/acetype"
)

const (
	SDDL_ACCESS_ALLOWED                 = "A"
	SDDL_ACCESS_DENIED                  = "D"
	SDDL_OBJECT_ACCESS_ALLOWED          = "OA"
	SDDL_OBJECT_ACCESS_DENIED           = "OD"
	SDDL_AUDIT                          = "AU"
	SDDL_ALARM                          = "AL"
	SDDL_OBJECT_AUDIT                   = "OU"
	SDDL_OBJECT_ALARM                   = "OL"
	SDDL_MANDATORY_LABEL                = "ML"
	SDDL_CALLBACK_ACCESS_ALLOWED        = "XA"
	SDDL_CALLBACK_ACCESS_DENIED         = "XD"
	SDDL_RESOURCE_ATTRIBUTE             = "RA"
	SDDL_SCOPED_POLICY_ID               = "SP"
	SDDL_CALLBACK_AUDIT                 = "XU"
	SDDL_CALLBACK_OBJECT_ACCESS_ALLOWED = "ZA"
	SDDL_PROCESS_TRUST_LABEL            = "TL"
	SDDL_ACCESS_FILTER                  = "FL"
)

var SDDLToACETypeMap = map[string]uint8{
	SDDL_ACCESS_ALLOWED:                 ntsd_acetype.ACE_TYPE_ACCESS_ALLOWED,
	SDDL_ACCESS_DENIED:                  ntsd_acetype.ACE_TYPE_ACCESS_DENIED,
	SDDL_OBJECT_ACCESS_ALLOWED:          ntsd_acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT,
	SDDL_OBJECT_ACCESS_DENIED:           ntsd_acetype.ACE_TYPE_ACCESS_DENIED_OBJECT,
	SDDL_AUDIT:                          ntsd_acetype.ACE_TYPE_SYSTEM_AUDIT,
	SDDL_ALARM:                          ntsd_acetype.ACE_TYPE_SYSTEM_ALARM,
	SDDL_OBJECT_AUDIT:                   ntsd_acetype.ACE_TYPE_SYSTEM_AUDIT_OBJECT,
	SDDL_OBJECT_ALARM:                   ntsd_acetype.ACE_TYPE_SYSTEM_ALARM_OBJECT,
	SDDL_MANDATORY_LABEL:                ntsd_acetype.ACE_TYPE_SYSTEM_MANDATORY_LABEL,
	SDDL_CALLBACK_ACCESS_ALLOWED:        ntsd_acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
	SDDL_CALLBACK_ACCESS_DENIED:         ntsd_acetype.ACE_TYPE_ACCESS_DENIED_CALLBACK,
	SDDL_RESOURCE_ATTRIBUTE:             ntsd_acetype.ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE,
	SDDL_SCOPED_POLICY_ID:               ntsd_acetype.ACE_TYPE_SYSTEM_SCOPED_POLICY_ID,
	SDDL_CALLBACK_AUDIT:                 ntsd_acetype.ACE_TYPE_SYSTEM_AUDIT_CALLBACK,
	SDDL_CALLBACK_OBJECT_ACCESS_ALLOWED: ntsd_acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
	// SDDL_PROCESS_TRUST_LABEL:            ntsd_ace.ACE_TYPE_SYSTEM_PROCESS_TRUST_LABEL,
	// SDDL_ACCESS_FILTER:                  ntsd_ace.ACE_TYPE_SYSTEM_ACCESS_FILTER,
}
