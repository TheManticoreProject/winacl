package securitydescriptor

import (
	"fmt"
	"strconv"
	"strings"

	ntsd_ace "github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/aceflags"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/acl"
	"github.com/TheManticoreProject/winacl/acl/revision"
	"github.com/TheManticoreProject/winacl/guid"
	"github.com/TheManticoreProject/winacl/identity"
	"github.com/TheManticoreProject/winacl/object"
	"github.com/TheManticoreProject/winacl/object/flags"
	"github.com/TheManticoreProject/winacl/securitydescriptor/control"
	"github.com/TheManticoreProject/winacl/sid"

	sddl_aceflags "github.com/TheManticoreProject/winacl/sddl/ace/aceflags"
	sddl_acetype "github.com/TheManticoreProject/winacl/sddl/ace/acetype"
	sddl_rights "github.com/TheManticoreProject/winacl/sddl/rights"
	sddl_sid "github.com/TheManticoreProject/winacl/sddl/sid"
)

// FromSDDLString initializes the NtSecurityDescriptor struct by parsing the SDDL string.
//
// Parameters:
//   - sddlString (string): The SDDL string to be parsed.
//
// Returns:
//   - (int, error): Always returns 0 for the int value, and an error if parsing fails.
func (ntsd *NtSecurityDescriptor) FromSDDLString(sddlString string) (int, error) {
	ownerStr, groupStr, daclFlags, daclAces, saclFlags, saclAces := cutSDDL(sddlString)

	ntsd.Header.Revision = 1

	// Parse owner
	if ownerStr != "" {
		ownerSID, err := sddlParseSID(ownerStr)
		if err != nil {
			return 0, fmt.Errorf("failed to parse owner SID '%s': %w", ownerStr, err)
		}
		ntsd.Owner = &identity.Identity{SID: *ownerSID}
		ntsd.Owner.Name = ownerSID.LookupName()
	}

	// Parse group
	if groupStr != "" {
		groupSID, err := sddlParseSID(groupStr)
		if err != nil {
			return 0, fmt.Errorf("failed to parse group SID '%s': %w", groupStr, err)
		}
		ntsd.Group = &identity.Identity{SID: *groupSID}
		ntsd.Group.Name = groupSID.LookupName()
	}

	// Parse DACL
	if len(daclAces) > 0 || daclFlags != "" {
		var entries []ntsd_ace.AccessControlEntry
		if len(daclAces) > 0 {
			var err error
			entries, err = sddlParseACL(daclAces)
			if err != nil {
				return 0, fmt.Errorf("failed to parse DACL: %w", err)
			}
		}
		ntsd.DACL = &acl.DiscretionaryAccessControlList{
			Header:  acl.DiscretionaryAccessControlListHeader{},
			Entries: entries,
		}
		ntsd.DACL.Header.Revision.Value = sddlGetACLRevision(entries)
		ntsd.DACL.Header.AceCount = uint16(len(entries))
		ntsd.Header.Control.RawValue |= control.NT_SECURITY_DESCRIPTOR_CONTROL_DP

		// Parse DACL flags
		if daclFlags != "" {
			controlBits, err := sddlParseACLFlags(daclFlags, true)
			if err != nil {
				return 0, fmt.Errorf("failed to parse DACL flags '%s': %w", daclFlags, err)
			}
			ntsd.Header.Control.RawValue |= controlBits
		}
	}

	// Parse SACL
	if len(saclAces) > 0 || saclFlags != "" {
		var entries []ntsd_ace.AccessControlEntry
		if len(saclAces) > 0 {
			var err error
			entries, err = sddlParseACL(saclAces)
			if err != nil {
				return 0, fmt.Errorf("failed to parse SACL: %w", err)
			}
		}
		ntsd.SACL = &acl.SystemAccessControlList{
			Header:  acl.SystemAccessControlListHeader{},
			Entries: entries,
		}
		ntsd.SACL.Header.Revision.Value = sddlGetACLRevision(entries)
		ntsd.SACL.Header.AceCount = uint16(len(entries))
		ntsd.Header.Control.RawValue |= control.NT_SECURITY_DESCRIPTOR_CONTROL_SP

		// Parse SACL flags
		if saclFlags != "" {
			controlBits, err := sddlParseACLFlags(saclFlags, false)
			if err != nil {
				return 0, fmt.Errorf("failed to parse SACL flags '%s': %w", saclFlags, err)
			}
			ntsd.Header.Control.RawValue |= controlBits
		}
	}

	// Set self-relative flag
	ntsd.Header.Control.RawValue |= control.NT_SECURITY_DESCRIPTOR_CONTROL_SR

	return 0, nil
}

// ToSDDLString converts the NtSecurityDescriptor to an SDDL string representation.
//
// Returns:
//   - (string, error): The SDDL string representation and any error that occurred.
func (ntsd *NtSecurityDescriptor) ToSDDLString() (string, error) {
	var sb strings.Builder

	// Owner
	if ntsd.Owner != nil {
		sb.WriteString("O:")
		sb.WriteString(sddlSIDToString(&ntsd.Owner.SID))
	}

	// Group
	if ntsd.Group != nil {
		sb.WriteString("G:")
		sb.WriteString(sddlSIDToString(&ntsd.Group.SID))
	}

	// DACL
	if ntsd.DACL != nil {
		sb.WriteString("D:")
		sb.WriteString(sddlACLFlagsToString(ntsd.Header.Control.RawValue, true))
		for _, entry := range ntsd.DACL.Entries {
			aceStr, err := sddlACEToString(&entry)
			if err != nil {
				return "", fmt.Errorf("failed to convert DACL ACE to SDDL: %w", err)
			}
			sb.WriteString("(")
			sb.WriteString(aceStr)
			sb.WriteString(")")
		}
	}

	// SACL
	if ntsd.SACL != nil {
		sb.WriteString("S:")
		sb.WriteString(sddlACLFlagsToString(ntsd.Header.Control.RawValue, false))
		for _, entry := range ntsd.SACL.Entries {
			aceStr, err := sddlACEToString(&entry)
			if err != nil {
				return "", fmt.Errorf("failed to convert SACL ACE to SDDL: %w", err)
			}
			sb.WriteString("(")
			sb.WriteString(aceStr)
			sb.WriteString(")")
		}
	}

	return sb.String(), nil
}

// cutSDDL parses an SDDL string into its component parts.
// This is a local copy to avoid circular imports with the sddl package.
// Returns: owner, group, daclFlags, daclAces, saclFlags, saclAces
func cutSDDL(sddlString string) (string, string, string, []string, string, []string) {
	sddlString = strings.TrimSpace(sddlString)
	if len(sddlString) == 0 {
		return "", "", "", nil, "", nil
	}

	components := map[string]string{
		"O:": "",
		"G:": "",
		"D:": "",
		"S:": "",
	}

	currentComponent := ""
	k := 0
	for k < len(sddlString) {
		upperChar := strings.ToUpper(string(sddlString[k]))
		if k+1 < len(sddlString) && (upperChar == "O" || upperChar == "G" || upperChar == "D" || upperChar == "S") && sddlString[k+1] == ':' {
			currentComponent = upperChar + ":"
			k += 2
			continue
		}
		if currentComponent != "" {
			components[currentComponent] += string(sddlString[k])
		}
		k++
	}

	daclFlags, daclAces := cutAces(components["D:"])
	saclFlags, saclAces := cutAces(components["S:"])

	return components["O:"], components["G:"], daclFlags, daclAces, saclFlags, saclAces
}

// cutAces extracts the ACL flags prefix and individual ACE strings from a DACL/SACL component.
func cutAces(aclStr string) (string, []string) {
	var aces []string

	start := strings.Index(aclStr, "(")
	if start == -1 {
		// No ACEs; everything is flags (or empty)
		return strings.TrimSpace(aclStr), aces
	}

	aclFlags := strings.TrimSpace(aclStr[:start])

	depth := 0
	aceStart := start
	for i := start; i < len(aclStr); i++ {
		switch aclStr[i] {
		case '(':
			if depth == 0 {
				aceStart = i + 1
			}
			depth++
		case ')':
			depth--
			if depth == 0 {
				aces = append(aces, aclStr[aceStart:i])
			}
		}
	}

	return aclFlags, aces
}

// sddlParseSID parses a SID from an SDDL string (abbreviation or full SID).
func sddlParseSID(s string) (*sid.SID, error) {
	s = strings.TrimSpace(s)

	// Check if it's a well-known SDDL abbreviation
	if fullSID, ok := sddl_sid.SDDLToSID[s]; ok {
		s = fullSID
	}

	if !strings.HasPrefix(s, "S-") {
		return nil, fmt.Errorf("unknown SID format: %s", s)
	}

	result := &sid.SID{}
	err := result.FromString(s)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// sddlSIDToString converts a SID to its SDDL string representation.
func sddlSIDToString(s *sid.SID) string {
	sidStr := s.ToString()
	if abbrev, ok := sddl_sid.SIDToSDDL[sidStr]; ok {
		return abbrev
	}
	return sidStr
}

// sddlParseACL parses a list of SDDL ACE strings into AccessControlEntry structs.
func sddlParseACL(aceStrings []string) ([]ntsd_ace.AccessControlEntry, error) {
	entries := make([]ntsd_ace.AccessControlEntry, 0, len(aceStrings))
	for i, aceStr := range aceStrings {
		entry, err := sddlParseACE(aceStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ACE #%d '%s': %w", i+1, aceStr, err)
		}
		entry.Index = uint16(i + 1)
		entries = append(entries, *entry)
	}
	return entries, nil
}

// sddlParseACE parses a single SDDL ACE string.
// Format: aceType;aceFlags;rights;objectGuid;inheritedObjectGuid;accountSid
func sddlParseACE(aceStr string) (*ntsd_ace.AccessControlEntry, error) {
	parts := strings.Split(aceStr, ";")
	if len(parts) < 6 {
		return nil, fmt.Errorf("invalid ACE string format, expected 6 semicolon-separated fields: %s", aceStr)
	}

	ace := &ntsd_ace.AccessControlEntry{}

	// Parse ACE type
	aceTypeStr := strings.TrimSpace(parts[0])
	if typeVal, ok := sddl_acetype.SDDLToACETypeMap[aceTypeStr]; ok {
		ace.Header.Type.Value = typeVal
	} else {
		return nil, fmt.Errorf("unknown ACE type: %s", aceTypeStr)
	}

	// Parse ACE flags
	flagsStr := strings.TrimSpace(parts[1])
	flagValue, err := sddlParseACEFlags(flagsStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ACE flags '%s': %w", flagsStr, err)
	}
	ace.Header.Flags.RawValue = flagValue
	ace.Header.Flags.Unmarshal([]byte{flagValue})

	// Parse rights/mask
	rightsStr := strings.TrimSpace(parts[2])
	maskValue, err := sddlParseRights(rightsStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rights '%s': %w", rightsStr, err)
	}
	ace.Mask.RawValue = maskValue

	// Parse object GUID
	objectGuidStr := strings.TrimSpace(parts[3])
	inheritedGuidStr := strings.TrimSpace(parts[4])

	if objectGuidStr != "" || inheritedGuidStr != "" {
		ace.AccessControlObjectType = object.AccessControlObjectType{}

		if objectGuidStr != "" {
			g, err := guid.FromString(objectGuidStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse object GUID '%s': %w", objectGuidStr, err)
			}
			ace.AccessControlObjectType.ObjectType.GUID = *g
			ace.AccessControlObjectType.Flags.Value |= flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT
		}

		if inheritedGuidStr != "" {
			g, err := guid.FromString(inheritedGuidStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse inherited object GUID '%s': %w", inheritedGuidStr, err)
			}
			ace.AccessControlObjectType.InheritedObjectType.GUID = *g
			ace.AccessControlObjectType.Flags.Value |= flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT
		}
	}

	// Parse account SID
	sidStr := strings.TrimSpace(parts[5])
	if sidStr != "" {
		parsedSID, err := sddlParseSID(sidStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse account SID '%s': %w", sidStr, err)
		}
		ace.Identity.SID = *parsedSID
		ace.Identity.Name = parsedSID.LookupName()
	}

	return ace, nil
}

// sddlParseACEFlags parses an SDDL ACE flags string into a combined uint8 value.
func sddlParseACEFlags(s string) (uint8, error) {
	if s == "" {
		return 0, nil
	}

	if len(s)%2 != 0 {
		return 0, fmt.Errorf("invalid ACE flags string (odd length): %s", s)
	}

	var result uint8
	for i := 0; i+1 < len(s); i += 2 {
		abbrev := s[i : i+2]
		if flagVal, ok := sddl_aceflags.SDDLToACEFlag[abbrev]; ok {
			result |= flagVal
		} else {
			return 0, fmt.Errorf("unknown ACE flag: %s", abbrev)
		}
	}
	return result, nil
}

// sddlParseRights parses an SDDL rights string into a uint32 access mask.
func sddlParseRights(s string) (uint32, error) {
	if s == "" {
		return 0, nil
	}

	// Check for hex value
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, err := strconv.ParseUint(s[2:], 16, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid hex rights value: %s", s)
		}
		return uint32(val), nil
	}

	if len(s)%2 != 0 {
		return 0, fmt.Errorf("invalid rights string (odd length): %s", s)
	}

	var result uint32
	for i := 0; i+1 < len(s); i += 2 {
		abbrev := s[i : i+2]
		if rightVal, ok := sddl_rights.SDDLToRight[abbrev]; ok {
			result |= rightVal
		} else {
			return 0, fmt.Errorf("unknown right: %s", abbrev)
		}
	}
	return result, nil
}

// sddlACEToString converts an AccessControlEntry to its SDDL string.
func sddlACEToString(ace *ntsd_ace.AccessControlEntry) (string, error) {
	var parts [6]string

	// ACE type
	typeStr, err := sddlACETypeToString(ace.Header.Type.Value)
	if err != nil {
		return "", err
	}
	parts[0] = typeStr

	// ACE flags
	parts[1] = sddlACEFlagsToString(ace.Header.Flags.RawValue)

	// Rights - pass ACE type for context-aware mapping
	parts[2] = sddlRightsToString(ace.Mask.RawValue, ace.Header.Type.Value)

	// Object GUID
	if ace.AccessControlObjectType.Flags.Value&flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT != 0 {
		parts[3] = ace.AccessControlObjectType.ObjectType.GUID.ToFormatD()
	}

	// Inherited object GUID
	if ace.AccessControlObjectType.Flags.Value&flags.ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT != 0 {
		parts[4] = ace.AccessControlObjectType.InheritedObjectType.GUID.ToFormatD()
	}

	// Account SID (only emit if the SID is initialized)
	if ace.Identity.SID.RevisionLevel != 0 {
		parts[5] = sddlSIDToString(&ace.Identity.SID)
	}

	return strings.Join(parts[:], ";"), nil
}

// sddlACETypeToString converts an ACE type value to its SDDL abbreviation.
func sddlACETypeToString(typeVal uint8) (string, error) {
	for sddl, val := range sddl_acetype.SDDLToACETypeMap {
		if val == typeVal {
			return sddl, nil
		}
	}
	return "", fmt.Errorf("unknown ACE type value: 0x%02x", typeVal)
}

// sddlACEFlagsToString converts ACE flags to their SDDL string.
func sddlACEFlagsToString(flagVal uint8) string {
	if flagVal == 0 {
		return ""
	}

	var sb strings.Builder
	orderedFlags := []struct {
		flag uint8
		sddl string
	}{
		{aceflags.ACE_FLAG_CONTAINER_INHERIT, "CI"},
		{aceflags.ACE_FLAG_OBJECT_INHERIT, "OI"},
		{aceflags.ACE_FLAG_NO_PROPAGATE_INHERIT, "NP"},
		{aceflags.ACE_FLAG_INHERIT_ONLY, "IO"},
		{aceflags.ACE_FLAG_INHERITED, "ID"},
		{aceflags.ACE_FLAG_SUCCESSFUL_ACCESS, "SA"},
		{aceflags.ACE_FLAG_FAILED_ACCESS, "FA"},
	}

	for _, of := range orderedFlags {
		if flagVal&of.flag != 0 {
			sb.WriteString(of.sddl)
		}
	}

	return sb.String()
}

// sddlRightsToString converts an access mask to its SDDL string.
// The aceType parameter is used to disambiguate rights that share the same
// bit value but have different SDDL abbreviations depending on context
// (e.g. mandatory label rights NR/NW/NX vs DS rights CC/DC/LC).
func sddlRightsToString(maskVal uint32, aceType uint8) string {
	if maskVal == 0 {
		return ""
	}

	// Try composite rights first (exact match)
	compositeRights := []struct {
		value uint32
		sddl  string
	}{
		{0x001F01FF, "FA"}, // FILE_ALL_ACCESS
		{0x000F003F, "KA"}, // KEY_ALL_ACCESS
	}
	for _, cr := range compositeRights {
		if maskVal == cr.value {
			return cr.sddl
		}
	}

	// For mandatory label ACEs, use NR/NW/NX abbreviations
	isMandatoryLabel := aceType == acetype.ACE_TYPE_SYSTEM_MANDATORY_LABEL

	var sb strings.Builder
	remaining := maskVal

	if isMandatoryLabel {
		mandatoryRights := []struct {
			value uint32
			sddl  string
		}{
			{0x00000001, "NR"}, // SYSTEM_MANDATORY_LABEL_NO_READ_UP
			{0x00000002, "NW"}, // SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
			{0x00000004, "NX"}, // SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
		}
		for _, mr := range mandatoryRights {
			if remaining&mr.value == mr.value {
				sb.WriteString(mr.sddl)
				remaining &^= mr.value
			}
		}
	}

	orderedRights := []struct {
		value uint32
		sddl  string
	}{
		// Generic rights
		{0x10000000, "GA"},
		{0x80000000, "GR"},
		{0x40000000, "GW"},
		{0x20000000, "GX"},
		// Standard rights
		{0x00020000, "RC"},
		{0x00010000, "SD"},
		{0x00040000, "WD"},
		{0x00080000, "WO"},
		// DS rights
		{0x00000010, "RP"},
		{0x00000020, "WP"},
		{0x00000001, "CC"},
		{0x00000002, "DC"},
		{0x00000004, "LC"},
		{0x00000008, "SW"},
		{0x00000080, "LO"},
		{0x00000040, "DT"},
		{0x00000100, "CR"},
	}

	for _, or := range orderedRights {
		if remaining&or.value == or.value {
			sb.WriteString(or.sddl)
			remaining &^= or.value
		}
	}

	if remaining != 0 {
		sb.WriteString(fmt.Sprintf("0x%08x", remaining))
	}

	return sb.String()
}

// sddlParseACLFlags parses SDDL ACL flags (P, AI, AR, NO_ACCESS_CONTROL) into control bits.
// isDACL determines whether the flags apply to the DACL or SACL.
func sddlParseACLFlags(s string, isDACL bool) (uint16, error) {
	var result uint16
	i := 0
	for i < len(s) {
		remaining := s[i:]
		matched := false

		// Try two-character flags first
		if len(remaining) >= 2 {
			twoChar := strings.ToUpper(remaining[:2])
			switch twoChar {
			case "AI":
				if isDACL {
					result |= control.NT_SECURITY_DESCRIPTOR_CONTROL_DI
				} else {
					result |= control.NT_SECURITY_DESCRIPTOR_CONTROL_SI
				}
				i += 2
				matched = true
			case "AR":
				if isDACL {
					result |= control.NT_SECURITY_DESCRIPTOR_CONTROL_DC
				} else {
					result |= control.NT_SECURITY_DESCRIPTOR_CONTROL_SC
				}
				i += 2
				matched = true
			}
		}

		if !matched {
			oneChar := strings.ToUpper(remaining[:1])
			switch oneChar {
			case "P":
				if isDACL {
					result |= control.NT_SECURITY_DESCRIPTOR_CONTROL_PD
				} else {
					result |= control.NT_SECURITY_DESCRIPTOR_CONTROL_PS
				}
				i++
			default:
				return 0, fmt.Errorf("unknown ACL flag at position %d: %s", i, remaining)
			}
		}
	}
	return result, nil
}

// sddlACLFlagsToString converts control bits to SDDL ACL flags string.
// isDACL determines whether to check DACL or SACL control bits.
func sddlACLFlagsToString(controlVal uint16, isDACL bool) string {
	var sb strings.Builder

	if isDACL {
		if controlVal&control.NT_SECURITY_DESCRIPTOR_CONTROL_PD != 0 {
			sb.WriteString("P")
		}
		if controlVal&control.NT_SECURITY_DESCRIPTOR_CONTROL_DI != 0 {
			sb.WriteString("AI")
		}
		if controlVal&control.NT_SECURITY_DESCRIPTOR_CONTROL_DC != 0 {
			sb.WriteString("AR")
		}
	} else {
		if controlVal&control.NT_SECURITY_DESCRIPTOR_CONTROL_PS != 0 {
			sb.WriteString("P")
		}
		if controlVal&control.NT_SECURITY_DESCRIPTOR_CONTROL_SI != 0 {
			sb.WriteString("AI")
		}
		if controlVal&control.NT_SECURITY_DESCRIPTOR_CONTROL_SC != 0 {
			sb.WriteString("AR")
		}
	}

	return sb.String()
}

// sddlGetACLRevision returns the appropriate ACL revision.
func sddlGetACLRevision(entries []ntsd_ace.AccessControlEntry) uint8 {
	for _, entry := range entries {
		switch entry.Header.Type.Value {
		case acetype.ACE_TYPE_ACCESS_ALLOWED_OBJECT,
			acetype.ACE_TYPE_ACCESS_DENIED_OBJECT,
			acetype.ACE_TYPE_SYSTEM_AUDIT_OBJECT,
			acetype.ACE_TYPE_SYSTEM_ALARM_OBJECT,
			acetype.ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
			acetype.ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
			acetype.ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT,
			acetype.ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT:
			return revision.ACL_REVISION_DS
		}
	}
	return revision.ACL_REVISION
}
