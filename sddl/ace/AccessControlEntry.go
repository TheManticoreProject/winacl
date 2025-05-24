package ace

// ParseSDDLAceString parses an SDDL ACE string into an NT Security Descriptor ACE.
//
// The SDDL ACE string format is: aceType;aceFlags;rights;objectGuid;inheritedObjectGuid;accountSid
// Example: "A;OICI;GA;;;BA"
//
// Parameters:
//   - aceString (string): The SDDL ACE string to parse
//
// Returns:
//   - (*ntsd_ace.AccessControlEntry, error): The parsed ACE and any error that occurred
// func ParseSDDLAceString(aceString string) (*ntsd_ace.AccessControlEntry, error) {
// 	// Split the ACE string into components
// 	parts := strings.Split(aceString, ";")
// 	if len(parts) < 6 {
// 		return nil, fmt.Errorf("invalid ACE string format: %s", aceString)
// 	}

// 	aceType := parts[0]
// 	aceFlags := parts[1]
// 	rights := parts[2]
// 	objectGuid := parts[3]
// 	inheritedObjectGuid := parts[4]
// 	accountSid := parts[5]

// 	// Create new ACE
// 	ace := &ntsd_ace.AccessControlEntry{}

// 	// Parse the ACE type
// 	if _, ok := SDDLToACETypeMap[aceType]; ok {
// 		ace.Header.Type.SetType(SDDLToACETypeMap[aceType])
// 	} else {
// 		return nil, fmt.Errorf("invalid ACE type: %s", aceType)
// 	}

// 	// Parse the ACE flags
// 	if _, ok := SDDLToACEFlagsMap[aceFlags]; ok {
// 		ace.Header.Flags.SetFlags(SDDLToACEFlagsMap[aceFlags])
// 	} else {
// 		return nil, fmt.Errorf("invalid ACE flags: %s", aceFlags)
// 	}

// 	// Parse the rights
// 	if _, ok := SDDLToACERightsMap[rights]; ok {
// 		ace.Mask.SetRights(SDDLToACERightsMap[rights])
// 	} else {
// 		return nil, fmt.Errorf("invalid ACE rights: %s", rights)
// 	}

// 	// Parse the object GUID
// 	if objectGuid != "" {
// 		ace.ObjectGuid.SetObjectGuid(objectGuid)
// 	}

// 	// Parse the inherited object GUID
// 	if inheritedObjectGuid != "" {
// 		ace.InheritedObjectGuid.SetObjectGuid(inheritedObjectGuid)
// 	}

// 	// Parse the account SID
// 	if accountSid != "" {
// 		ace.SID.SetSID(accountSid)
// 	}

// 	return ace, nil
// }
