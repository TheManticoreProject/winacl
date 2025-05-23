package identity

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const (
	WELLKNOWNSID_NOBODY               = "S-1-0-0"
	WELLKNOWNSID_EVERYONE             = "S-1-1-0"
	WELLKNOWNSID_LOCAL                = "S-1-2-0"
	WELLKNOWNSID_CONSOLE_LOGON        = "S-1-2-1"
	WELLKNOWNSID_CREATOR_OWNER        = "S-1-3-0"
	WELLKNOWNSID_CREATOR_GROUP        = "S-1-3-1"
	WELLKNOWNSID_CREATOR_OWNER_SERVER = "S-1-3-2"
	WELLKNOWNSID_CREATOR_GROUP_SERVER = "S-1-3-3"
	// NT\Authority
	WELLKNOWNSID_NT_AUTHORITY                               = "S-1-5"
	WELLKNOWNSID_NT_AUTHORITY_DIALUP                        = "S-1-5-1"
	WELLKNOWNSID_NT_AUTHORITY_NETWORK                       = "S-1-5-2"
	WELLKNOWNSID_NT_AUTHORITY_BATCH                         = "S-1-5-3"
	WELLKNOWNSID_NT_AUTHORITY_INTERACTIVE                   = "S-1-5-4"
	WELLKNOWNSID_NT_AUTHORITY_SERVICE                       = "S-1-5-6"
	WELLKNOWNSID_NT_AUTHORITY_ANONYMOUS                     = "S-1-5-7"
	WELLKNOWNSID_NT_AUTHORITY_PROXY                         = "S-1-5-8"
	WELLKNOWNSID_NT_AUTHORITY_ENTERPRISE_DOMAIN_CONTROLLERS = "S-1-5-9"
	WELLKNOWNSID_NT_AUTHORITY_PRINCIPAL_SELF                = "S-1-5-10"
	WELLKNOWNSID_NT_AUTHORITY_AUTHENTICATED_USERS           = "S-1-5-11"
	WELLKNOWNSID_NT_AUTHORITY_RESTRICTED_CODE               = "S-1-5-12"
	WELLKNOWNSID_NT_AUTHORITY_TERMINAL_SERVER_USERS         = "S-1-5-13"
	WELLKNOWNSID_NT_AUTHORITY_REMOTE_INTERACTIVE_LOGON      = "S-1-5-14"
	WELLKNOWNSID_NT_AUTHORITY_THIS_ORGANIZATION             = "S-1-5-15"
	WELLKNOWNSID_NT_AUTHORITY_IUSR                          = "S-1-5-17"
	WELLKNOWNSID_NT_AUTHORITY_LOCAL_SYSTEM                  = "S-1-5-18"
	WELLKNOWNSID_NT_AUTHORITY_LOCAL_SERVICE                 = "S-1-5-19"
	WELLKNOWNSID_NT_AUTHORITY_NETWORK_SERVICE               = "S-1-5-20"
	WELLKNOWNSID_NT_AUTHORITY_NTLM_AUTHENTICATION           = "S-1-5-64-10"
	WELLKNOWNSID_NT_AUTHORITY_SCHANNEL_AUTHENTICATION       = "S-1-5-64-14"
	WELLKNOWNSID_NT_AUTHORITY_DIGEST_AUTHENTICATION         = "S-1-5-64-21"
	// Mandatory Label
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_UNTRUSTED_LEVEL             = "S-1-16-0"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_LOW_INTEGRITY_LEVEL         = "S-1-16-4096"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_MEDIUM_INTEGRITY_LEVEL      = "S-1-16-8192"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_MEDIUM_PLUS_INTEGRITY_LEVEL = "S-1-16-8448"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_HIGH_INTEGRITY_LEVEL        = "S-1-16-12288"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_SYSTEM_INTEGRITY_LEVEL      = "S-1-16-16384"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_PROTECTED_PROCESS           = "S-1-16-20480"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_SECURE_PROCESS              = "S-1-16-28672"
	//
	WELLKNOWNSID_DOMAIN_ADMINISTRATOR_ACCOUNT        = "S-1-5-21-0-0-0-500"
	WELLKNOWNSID_DOMAIN_GUEST_ACCOUNT                = "S-1-5-21-0-0-0-501"
	WELLKNOWNSID_DOMAIN_KRBTGT_ACCOUNT               = "S-1-5-21-0-0-0-502"
	WELLKNOWNSID_DOMAIN_ADMINS                       = "S-1-5-21-0-0-0-512"
	WELLKNOWNSID_DOMAIN_USERS                        = "S-1-5-21-0-0-0-513"
	WELLKNOWNSID_DOMAIN_GUESTS                       = "S-1-5-21-0-0-0-514"
	WELLKNOWNSID_DOMAIN_COMPUTERS                    = "S-1-5-21-0-0-0-515"
	WELLKNOWNSID_DOMAIN_CONTROLLERS                  = "S-1-5-21-0-0-0-516"
	WELLKNOWNSID_DOMAIN_CERT_PUBLISHERS              = "S-1-5-21-0-0-0-517"
	WELLKNOWNSID_DOMAIN_SCHEMA_ADMINS                = "S-1-5-21-0-0-0-518"
	WELLKNOWNSID_DOMAIN_ENTERPRISE_ADMINS            = "S-1-5-21-0-0-0-519"
	WELLKNOWNSID_DOMAIN_GROUP_POLICY_CREATOR_OWNERS  = "S-1-5-21-0-0-0-520"
	WELLKNOWNSID_DOMAIN_READ_ONLY_DOMAIN_CONTROLLERS = "S-1-5-21-0-0-0-521"
	WELLKNOWNSID_DOMAIN_CLONEABLE_DOMAIN_CONTROLLERS = "S-1-5-21-0-0-0-522"
	WELLKNOWNSID_DOMAIN_RAS_SERVERS_GROUP            = "S-1-5-21-0-0-0-553"
	// BUILTIN
	WELLKNOWNSID_BUILTIN_DOMAIN                              = "S-1-5-32"
	WELLKNOWNSID_BUILTIN_ADMINISTRATORS                      = "S-1-5-32-544"
	WELLKNOWNSID_BUILTIN_USERS                               = "S-1-5-32-545"
	WELLKNOWNSID_BUILTIN_GUESTS                              = "S-1-5-32-546"
	WELLKNOWNSID_BUILTIN_POWER_USERS                         = "S-1-5-32-547"
	WELLKNOWNSID_BUILTIN_ACCOUNT_OPERATORS                   = "S-1-5-32-548"
	WELLKNOWNSID_BUILTIN_SERVER_OPERATORS                    = "S-1-5-32-549"
	WELLKNOWNSID_BUILTIN_PRINT_OPERATORS                     = "S-1-5-32-550"
	WELLKNOWNSID_BUILTIN_BACKUP_OPERATORS                    = "S-1-5-32-551"
	WELLKNOWNSID_BUILTIN_REPLICATORS                         = "S-1-5-32-552"
	WELLKNOWNSID_BUILTIN_PRE_WINDOWS_2000_COMPATIBLE_ACCESS  = "S-1-5-32-554"
	WELLKNOWNSID_BUILTIN_REMOTE_DESKTOP_USERS                = "S-1-5-32-555"
	WELLKNOWNSID_BUILTIN_NETWORK_CONFIGURATION_OPERATORS     = "S-1-5-32-556"
	WELLKNOWNSID_BUILTIN_INCOMING_FOREST_TRUST_BUILDERS      = "S-1-5-32-557"
	WELLKNOWNSID_BUILTIN_PERFORMANCE_MONITOR_USERS           = "S-1-5-32-558"
	WELLKNOWNSID_BUILTIN_PERFORMANCE_LOG_USERS               = "S-1-5-32-559"
	WELLKNOWNSID_BUILTIN_WINDOWS_AUTHORIZATION_ACCESS_GROUP  = "S-1-5-32-560"
	WELLKNOWNSID_BUILTIN_TERMINAL_SERVER_LICENSE_SERVERS     = "S-1-5-32-561"
	WELLKNOWNSID_BUILTIN_DISTRIBUTED_COM_USERS               = "S-1-5-32-562"
	WELLKNOWNSID_BUILTIN_CRYPTOGRAPHIC_OPERATORS             = "S-1-5-32-569"
	WELLKNOWNSID_BUILTIN_EVENT_LOG_READERS                   = "S-1-5-32-573"
	WELLKNOWNSID_BUILTIN_CERTIFICATE_SERVICE_DCOM_ACCESS     = "S-1-5-32-574"
	WELLKNOWNSID_BUILTIN_RDS_REMOTE_ACCESS_SERVERS           = "S-1-5-32-575"
	WELLKNOWNSID_BUILTIN_RDS_ENDPOINT_SERVERS                = "S-1-5-32-576"
	WELLKNOWNSID_BUILTIN_RDS_MANAGEMENT_SERVERS              = "S-1-5-32-577"
	WELLKNOWNSID_BUILTIN_HYPER_V_ADMINISTRATORS              = "S-1-5-32-578"
	WELLKNOWNSID_BUILTIN_ACCESS_CONTROL_ASSISTANCE_OPERATORS = "S-1-5-32-579"
	WELLKNOWNSID_BUILTIN_REMOTE_MANAGEMENT_USERS             = "S-1-5-32-580"
)

// WellKnownSIDs maps some well-known SIDs to their names.
var WellKnownSIDs = map[string]string{
	// Operating system-defined SIDs
	WELLKNOWNSID_NOBODY:               "Nobody",
	WELLKNOWNSID_EVERYONE:             "Everyone",
	WELLKNOWNSID_LOCAL:                "Local",
	WELLKNOWNSID_CONSOLE_LOGON:        "Console Logon",
	WELLKNOWNSID_CREATOR_OWNER:        "Creator Owner",
	WELLKNOWNSID_CREATOR_GROUP:        "Creator Group",
	WELLKNOWNSID_CREATOR_OWNER_SERVER: "Creator Owner Server",
	WELLKNOWNSID_CREATOR_GROUP_SERVER: "Creator Group Server",

	// NT\Authority
	WELLKNOWNSID_NT_AUTHORITY:                               "NT Authority",
	WELLKNOWNSID_NT_AUTHORITY_DIALUP:                        "Dialup",
	WELLKNOWNSID_NT_AUTHORITY_NETWORK:                       "Network",
	WELLKNOWNSID_NT_AUTHORITY_BATCH:                         "Batch",
	WELLKNOWNSID_NT_AUTHORITY_INTERACTIVE:                   "Interactive",
	WELLKNOWNSID_NT_AUTHORITY_SERVICE:                       "Service",
	WELLKNOWNSID_NT_AUTHORITY_ANONYMOUS:                     "Anonymous",
	WELLKNOWNSID_NT_AUTHORITY_PROXY:                         "Proxy",
	WELLKNOWNSID_NT_AUTHORITY_ENTERPRISE_DOMAIN_CONTROLLERS: "Enterprise Domain Controllers",
	WELLKNOWNSID_NT_AUTHORITY_PRINCIPAL_SELF:                "Principal Self",
	WELLKNOWNSID_NT_AUTHORITY_AUTHENTICATED_USERS:           "Authenticated Users",
	WELLKNOWNSID_NT_AUTHORITY_RESTRICTED_CODE:               "Restricted Code",
	WELLKNOWNSID_NT_AUTHORITY_TERMINAL_SERVER_USERS:         "Terminal Server Users",
	WELLKNOWNSID_NT_AUTHORITY_REMOTE_INTERACTIVE_LOGON:      "Remote Interactive Logon",
	WELLKNOWNSID_NT_AUTHORITY_THIS_ORGANIZATION:             "This Organization",
	WELLKNOWNSID_NT_AUTHORITY_IUSR:                          "IUSR",
	WELLKNOWNSID_NT_AUTHORITY_LOCAL_SYSTEM:                  "Local System",
	WELLKNOWNSID_NT_AUTHORITY_LOCAL_SERVICE:                 "Local Service",
	WELLKNOWNSID_NT_AUTHORITY_NETWORK_SERVICE:               "Network Service",
	// NT\Authority Authentication Types
	WELLKNOWNSID_NT_AUTHORITY_NTLM_AUTHENTICATION:     "NTLM Authentication",
	WELLKNOWNSID_NT_AUTHORITY_SCHANNEL_AUTHENTICATION: "SChannel Authentication",
	WELLKNOWNSID_NT_AUTHORITY_DIGEST_AUTHENTICATION:   "Digest Authentication",

	// Built-in system groups
	WELLKNOWNSID_BUILTIN_DOMAIN:                              "BUILTIN",
	WELLKNOWNSID_BUILTIN_ADMINISTRATORS:                      "BUILTIN\\Administrators",
	WELLKNOWNSID_BUILTIN_USERS:                               "BUILTIN\\Users",
	WELLKNOWNSID_BUILTIN_GUESTS:                              "BUILTIN\\Guests",
	WELLKNOWNSID_BUILTIN_POWER_USERS:                         "BUILTIN\\Power Users",
	WELLKNOWNSID_BUILTIN_ACCOUNT_OPERATORS:                   "BUILTIN\\Account Operators",
	WELLKNOWNSID_BUILTIN_SERVER_OPERATORS:                    "BUILTIN\\Server Operators",
	WELLKNOWNSID_BUILTIN_PRINT_OPERATORS:                     "BUILTIN\\Print Operators",
	WELLKNOWNSID_BUILTIN_BACKUP_OPERATORS:                    "BUILTIN\\Backup Operators",
	WELLKNOWNSID_BUILTIN_REPLICATORS:                         "BUILTIN\\Replicators",
	WELLKNOWNSID_BUILTIN_PRE_WINDOWS_2000_COMPATIBLE_ACCESS:  "BUILTIN\\Pre-Windows 2000 Compatible Access",
	WELLKNOWNSID_BUILTIN_REMOTE_DESKTOP_USERS:                "BUILTIN\\Remote Desktop Users",
	WELLKNOWNSID_BUILTIN_NETWORK_CONFIGURATION_OPERATORS:     "BUILTIN\\Network Configuration Operators",
	WELLKNOWNSID_BUILTIN_INCOMING_FOREST_TRUST_BUILDERS:      "BUILTIN\\Incoming Forest Trust Builders",
	WELLKNOWNSID_BUILTIN_PERFORMANCE_MONITOR_USERS:           "BUILTIN\\Performance Monitor Users",
	WELLKNOWNSID_BUILTIN_PERFORMANCE_LOG_USERS:               "BUILTIN\\Performance Log Users",
	WELLKNOWNSID_BUILTIN_WINDOWS_AUTHORIZATION_ACCESS_GROUP:  "BUILTIN\\Windows Authorization Access Group",
	WELLKNOWNSID_BUILTIN_TERMINAL_SERVER_LICENSE_SERVERS:     "BUILTIN\\Terminal Server License Servers",
	WELLKNOWNSID_BUILTIN_DISTRIBUTED_COM_USERS:               "BUILTIN\\Distributed COM Users",
	WELLKNOWNSID_BUILTIN_CRYPTOGRAPHIC_OPERATORS:             "BUILTIN\\Cryptographic Operators",
	WELLKNOWNSID_BUILTIN_EVENT_LOG_READERS:                   "BUILTIN\\Event Log Readers",
	WELLKNOWNSID_BUILTIN_CERTIFICATE_SERVICE_DCOM_ACCESS:     "BUILTIN\\Certificate Service DCOM Access",
	WELLKNOWNSID_BUILTIN_RDS_REMOTE_ACCESS_SERVERS:           "BUILTIN\\RDS Remote Access Servers",
	WELLKNOWNSID_BUILTIN_RDS_ENDPOINT_SERVERS:                "BUILTIN\\RDS Endpoint Servers",
	WELLKNOWNSID_BUILTIN_RDS_MANAGEMENT_SERVERS:              "BUILTIN\\RDS Management Servers",
	WELLKNOWNSID_BUILTIN_HYPER_V_ADMINISTRATORS:              "BUILTIN\\Hyper-V Administrators",
	WELLKNOWNSID_BUILTIN_ACCESS_CONTROL_ASSISTANCE_OPERATORS: "BUILTIN\\Access Control Assistance Operators",
	WELLKNOWNSID_BUILTIN_REMOTE_MANAGEMENT_USERS:             "BUILTIN\\Remote Management Users",

	// Mandatory integrity levels
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_UNTRUSTED_LEVEL:             "Untrusted Level",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_LOW_INTEGRITY_LEVEL:         "Low Integrity Level",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_MEDIUM_INTEGRITY_LEVEL:      "Medium Integrity Level",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_MEDIUM_PLUS_INTEGRITY_LEVEL: "Medium Plus Integrity Level",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_HIGH_INTEGRITY_LEVEL:        "High Integrity Level",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_SYSTEM_INTEGRITY_LEVEL:      "System Integrity Level",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_PROTECTED_PROCESS:           "Protected Process",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_SECURE_PROCESS:              "Secure Process",

	// Special identity groups
	WELLKNOWNSID_DOMAIN_ADMINISTRATOR_ACCOUNT:        "Administrator Account",
	WELLKNOWNSID_DOMAIN_GUEST_ACCOUNT:                "Guest Account",
	WELLKNOWNSID_DOMAIN_KRBTGT_ACCOUNT:               "KRBTGT Account",
	WELLKNOWNSID_DOMAIN_ADMINS:                       "Domain Admins",
	WELLKNOWNSID_DOMAIN_USERS:                        "Domain Users",
	WELLKNOWNSID_DOMAIN_GUESTS:                       "Domain Guests",
	WELLKNOWNSID_DOMAIN_COMPUTERS:                    "Domain Computers",
	WELLKNOWNSID_DOMAIN_CONTROLLERS:                  "Domain Controllers",
	WELLKNOWNSID_DOMAIN_CERT_PUBLISHERS:              "Cert Publishers",
	WELLKNOWNSID_DOMAIN_SCHEMA_ADMINS:                "Schema Admins",
	WELLKNOWNSID_DOMAIN_ENTERPRISE_ADMINS:            "Enterprise Admins",
	WELLKNOWNSID_DOMAIN_GROUP_POLICY_CREATOR_OWNERS:  "Group Policy Creator Owners",
	WELLKNOWNSID_DOMAIN_READ_ONLY_DOMAIN_CONTROLLERS: "Read-Only Domain Controllers",
	WELLKNOWNSID_DOMAIN_CLONEABLE_DOMAIN_CONTROLLERS: "Cloneable Domain Controllers",
	WELLKNOWNSID_DOMAIN_RAS_SERVERS_GROUP:            "RAS Servers Group",
}

// Represents a Security Identifier (SID) in various formats and provides methods for manipulation and conversion between them.
//
// Attributes:
//
//	revisionLevel (int): The revision level of the SID.
//	subAuthorityCount (int): The number of sub-authorities in the SID.
//	identifierAuthority (SID_IDENTIFIER_AUTHORITY): The identifier authority value.
//	reserved (bytes): Reserved bytes, should always be empty.
//	subAuthorities (list): A list of sub-authorities.
//	relativeIdentifier (int): The relative identifier.
//
// Methods:
//
//		Parse(RawBytes []byte): Parses the raw bytes to populate the SID fields.
//		ToString() string: Converts the SID to its string representation.
//	 Describe(): prints a detailed description of the SID with the specified indentation level.
//
// See: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
type SID struct {
	RevisionLevel       uint8
	SubAuthorityCount   uint8
	IdentifierAuthority SecurityIdentifierAuthority
	SubAuthorities      []uint32
	RelativeIdentifier  uint32
	Reserved            []byte

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// IsWellKnownSID checks if the current SID instance matches any well-known SIDs,
// such as those that represent common Windows accounts (e.g., "Everyone", "Local System").
//
// Returns:
//   - bool: True if the SID is a well-known SID, otherwise false.
func (sid *SID) IsWellKnownSID() bool {
	// Check if the SID is in the map of well-known SIDs
	_, found := WellKnownSIDs[sid.ToString()]
	return found
}

// LookupName retrieves the name associated with the well-known SID if it exists.
// If the SID is not well-known, the method returns an empty string.
//
// Returns:
//   - string: The name of the well-known SID if found; otherwise, an empty string.
func (sid *SID) LookupName() string {
	// Check if it's a well-known SID and return its name
	if name, found := WellKnownSIDs[sid.ToString()]; found {
		return name
	}
	// If it's not a well-known SID, return an empty string
	return ""
}

// Unmarshal populates the SID struct fields from the provided byte slice,
// interpreting the byte data as a binary representation of a Security Identifier (SID).
//
// Parameters:
//   - RawBytes ([]byte): A byte slice containing the binary representation of the SID.
//     The slice must be at least of sufficient length to contain all SID components.
func (sid *SID) Unmarshal(marshalledData []byte) (int, error) {
	// Init all the fields
	sid.RevisionLevel = 0
	sid.SubAuthorityCount = 0
	sid.IdentifierAuthority = SecurityIdentifierAuthority{Value: 0}
	sid.SubAuthorities = make([]uint32, 0)
	sid.RelativeIdentifier = 0
	sid.Reserved = make([]byte, 0)

	sid.RawBytesSize = 0

	// Parse the RevisionLevel
	if len(marshalledData) > int(sid.RawBytesSize)+1 {
		sid.RevisionLevel = uint8(marshalledData[0])
		sid.RawBytesSize += 1
	} else {
		return 0, fmt.Errorf("not enough data to parse RevisionLevel")
	}

	// Parse the SubAuthorityCount
	if len(marshalledData) > int(sid.RawBytesSize)+1 {
		sid.SubAuthorityCount = uint8(marshalledData[1])
		sid.RawBytesSize += 1
	} else {
		return 0, fmt.Errorf("not enough data to parse SubAuthorityCount")
	}

	// Parse the IdentifierAuthority
	if len(marshalledData) >= int(sid.RawBytesSize)+6 {
		sid.IdentifierAuthority.Unmarshal(marshalledData[2:8])
		sid.RawBytesSize += 6
	} else {
		return 0, fmt.Errorf("not enough data to parse IdentifierAuthority")
	}

	// Initialize the sub-authorities
	if sid.SubAuthorityCount > 0 {
		sid.SubAuthorities = make([]uint32, sid.SubAuthorityCount-1)
		for i := 0; i < int(sid.SubAuthorityCount-1); i++ {
			sid.SubAuthorities[i] = 0
		}

		// Parse the real sub-authorities
		for i := 0; i < int(sid.SubAuthorityCount-1); i++ {
			if len(marshalledData) >= int(sid.RawBytesSize)+4 {
				sid.SubAuthorities[i] = binary.LittleEndian.Uint32(marshalledData[sid.RawBytesSize : sid.RawBytesSize+4])
				sid.RawBytesSize += 4
			} else {
				return 0, fmt.Errorf("not enough data to parse SubAuthority %d", i)
			}
		}
	}

	if int(sid.RawBytesSize) < len(marshalledData) {
		// Here we pad the relative identifier bytes to match the expected length of 4 bytes
		buffer := marshalledData[sid.RawBytesSize:]
		if len(buffer) < 4 {
			buffer = append(buffer, make([]byte, 4-len(buffer))...)
		}
		sid.RelativeIdentifier = binary.LittleEndian.Uint32(buffer)
		sid.RawBytesSize += uint32(len(buffer))
	}

	return int(sid.RawBytesSize), nil
}

// Marshal converts the current SID struct into its binary representation as a byte slice,
// suitable for storage or transmission.
//
// Returns:
//   - []byte: A byte slice representing the SID in binary format, constructed from its fields.
func (sid *SID) Marshal() ([]byte, error) {
	// Create a byte slice to hold the result
	marshalledData := make([]byte, 0)

	// Add the RevisionLevel
	marshalledData = append(marshalledData, sid.RevisionLevel)

	// Add the SubAuthorityCount
	marshalledData = append(marshalledData, sid.SubAuthorityCount)

	// Convert and add the IdentifierAuthority (6 bytes, big-endian)
	identifierBytes, err := sid.IdentifierAuthority.Marshal()
	if err != nil {
		return nil, err
	}
	marshalledData = append(marshalledData, identifierBytes...)

	// Add each sub-authority (4 bytes each, little-endian) up to the point where all remaining sub-authorities are 0
	lastNullSubAuthorityIndex := len(sid.SubAuthorities)
	for i := len(sid.SubAuthorities) - 1; i >= 0; i-- {
		if sid.SubAuthorities[i] != 0 {
			lastNullSubAuthorityIndex = i + 1
			break
		}
	}

	// Add each sub-authority (4 bytes each, little-endian)
	for k := 0; k < lastNullSubAuthorityIndex; k++ {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], sid.SubAuthorities[k])
		marshalledData = append(marshalledData, buf[:]...)
	}

	if sid.RelativeIdentifier != 0 {
		// Add the Relative Identifier (4 bytes, little-endian)
		relativeIdentifierBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(relativeIdentifierBytes, sid.RelativeIdentifier)
		marshalledData = append(marshalledData, relativeIdentifierBytes...)
	}

	return marshalledData, nil
}

// FromString populates the SID struct fields from a provided SID string representation.
// The expected format for the SID string is "S-<Revision>-<IdentifierAuthority>-<SubAuthority1>-<SubAuthority2>-...-<RID>".
//
// Parameters:
//   - sidString (string): The string representation of the SID to be parsed.
//
// Returns:
//   - error: Returns an error if the SID string format is invalid or if any part of the string
//     cannot be parsed correctly. Returns nil if the parsing is successful.
func (sid *SID) FromString(sidString string) error {
	// Init all the fields
	sid.RevisionLevel = 0
	sid.SubAuthorityCount = 0
	sid.IdentifierAuthority = SecurityIdentifierAuthority{Value: 0}
	sid.SubAuthorities = make([]uint32, 0)
	sid.RelativeIdentifier = 0
	sid.Reserved = make([]byte, 0)

	sid.RawBytesSize = 0

	// Split the SID string into parts using "-" as the delimiter
	parts := strings.Split(sidString, "-")

	// Ensure the SID string starts with "S" and has at least 4 parts: "S", revision, identifier authority, sub-authorities/RID
	if len(parts) < 4 || parts[0] != "S" {
		return fmt.Errorf("invalid SID string format")
	}

	// Parse the revision level (S-<Revision>)
	revision, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid revision level in SID: %v", err)
	}
	sid.RevisionLevel = uint8(revision)

	// Parse the identifier authority (S-<Revision>-<IdentifierAuthority>)
	identifierAuthority, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid identifier authority in SID: %v", err)
	}
	sid.IdentifierAuthority.Value = identifierAuthority

	// The rest are sub-authorities including the Relative Identifier (RID)
	subAuthorities := make([]uint32, 0)
	for i := 0; i < len(parts[3:]); i++ {
		subAuthority, err := strconv.ParseUint(parts[3+i], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid sub-authority in SID: %v", err)
		}
		subAuthorities = append(subAuthorities, uint32(subAuthority))
	}

	sid.RelativeIdentifier = 0
	sid.SubAuthorityCount = uint8(0)
	sid.SubAuthorities = make([]uint32, 0)
	// Determine SubAuthorityCount and set SubAuthorities/RID
	if len(subAuthorities) != 0 {
		if len(subAuthorities) == 1 {
			// The last sub-authority is the Relative Identifier (RID)
			sid.RelativeIdentifier = subAuthorities[len(subAuthorities)-1]
		} else {
			// The last sub-authority is the Relative Identifier (RID)
			sid.RelativeIdentifier = subAuthorities[len(subAuthorities)-1]
			// The rest are the sub-authorities
			sid.SubAuthorities = subAuthorities[:len(subAuthorities)-1]
			sid.SubAuthorityCount = uint8(len(subAuthorities))
		}
	}

	return nil
}

// ToString converts the SID struct into its string representation following the SID format:
// "S-<Revision>-<IdentifierAuthority>-<SubAuthority1>-<SubAuthority2>-...-<RID>".
//
// Returns:
//   - string: A string representation of the SID, formatted according to the SID structure.
//     This includes the revision level, identifier authority, all sub-authorities, and the
//     relative identifier (RID).
func (sid *SID) ToString() string {
	sidstring := fmt.Sprintf("S-%d-%d", sid.RevisionLevel, sid.IdentifierAuthority.Value)

	for k := range sid.SubAuthorities {
		sidstring += fmt.Sprintf("-%d", sid.SubAuthorities[k])
	}

	sidstring += fmt.Sprintf("-%d", sid.RelativeIdentifier)

	return sidstring
}

// String returns the string representation of the SID.
func (sid *SID) String() string {
	return sid.ToString()
}

// Describe prints a detailed description of the SID struct, including its various fields,
// formatted with indentation for clarity.
//
// Parameters:
//   - indent (int): The indentation level for formatting the output. Each level increases
//     the indentation depth, allowing for a hierarchical display of the SID's components.
func (sid *SID) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<SID '%s'>\n", indentPrompt, sid.ToString())
	fmt.Printf("%s │ \x1b[93mRevisionLevel\x1b[0m        : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, sid.RevisionLevel)
	fmt.Printf("%s │ \x1b[93mSubAuthorityCount\x1b[0m    : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, sid.SubAuthorityCount)
	fmt.Printf("%s │ \x1b[93mIdentifierAuthority\x1b[0m  : \x1b[96m0x%012x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, sid.IdentifierAuthority, sid.IdentifierAuthority.String())

	if sid.SubAuthorityCount != 0 {
		fmt.Printf("%s │ \x1b[93mSubAuthorities (%03d)\x1b[0m :\n", indentPrompt, sid.SubAuthorityCount)
		for index, subauthority := range sid.SubAuthorities {
			fmt.Printf("%s │ \x1b[93mSubAuthority %02d\x1b[0m   : \x1b[96m0x%08x\x1b[0m (\x1b[94m%d\x1b[0m)\n", strings.Repeat(" │ ", indent+1), index, subauthority, subauthority)
		}
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	} else {
		fmt.Printf("%s │ \x1b[93mSubAuthorities (0)\x1b[0m   : Empty\n", indentPrompt)
	}

	fmt.Printf("%s │ \x1b[93mRelativeIdentifier\x1b[0m   : \x1b[96m0x%08x\x1b[0m (\x1b[94m%d\x1b[0m)\n", indentPrompt, sid.RelativeIdentifier, sid.RelativeIdentifier)
	fmt.Printf("%s └─\n", indentPrompt)
}
