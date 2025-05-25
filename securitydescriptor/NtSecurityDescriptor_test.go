package securitydescriptor_test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/acl"
	"github.com/TheManticoreProject/winacl/rights"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

func TestNtSecurityDescriptor_Involution(t *testing.T) {
	// --------------------------------------------------------------------------------------------------------------75a38
	testNtsdHex := "0100149ccc000000e800000014000000a000000004008c00030000000240140020000c00010100000000000100000000075a38002000000003000000be3b0ef3f09fd111b6030000f80367c1a57a96bfe60dd011a28500aa003049e2010100000000000100000000075a38002000000003000000bf3b0ef3f09fd111b6030000f80367c1a57a96bfe60dd011a28500aa003049e201010000000000010000000002002c000100000000002400ff010f0001050000000000051500000028bb82279261b9fe2474aa5d0002000001050000000000051500000028bb82279261b9fe2474aa5d0002000001050000000000051500000028bb82279261b9fe20000000"

	ntsd := &securitydescriptor.NtSecurityDescriptor{}
	ntsdBytes, err := hex.DecodeString(testNtsdHex)
	if err != nil {
		t.Errorf("Failed to decode testNtsdHex: %v", err)
	}

	_, err = ntsd.Unmarshal(ntsdBytes)
	if err != nil {
		t.Errorf("Failed to unmarshal NtSecurityDescriptor: %v", err)
	}

	serializedBytes, err := ntsd.Marshal()
	if err != nil {
		t.Errorf("Failed to marshal NtSecurityDescriptor: %v", err)
	}
	hexData1 := hex.EncodeToString(serializedBytes)

	if !strings.EqualFold(testNtsdHex, hexData1) {
		minLen := len(hexData1)
		if len(testNtsdHex) < minLen {
			minLen = len(testNtsdHex)
		}
		for k := 0; k < minLen; k++ {
			if hexData1[k] == testNtsdHex[k] {
				hexData1 = hexData1[:k] + "_" + hexData1[k+1:]
				testNtsdHex = testNtsdHex[:k] + "_" + testNtsdHex[k+1:]
			}
		}

		fmt.Println("output-:", hexData1)
		fmt.Println("input--:", testNtsdHex)

		t.Errorf("NtSecurityDescriptor.Marshal() failed: Output of ntsd.Marshal() is not equal to input hex string")
	}

	ntsd2 := &securitydescriptor.NtSecurityDescriptor{}
	_, err = ntsd2.Unmarshal(serializedBytes)
	if err != nil {
		t.Errorf("Failed to unmarshal NtSecurityDescriptor: %v", err)
	}
	data2, err := ntsd2.Marshal()
	if err != nil {
		t.Errorf("Failed to marshal NtSecurityDescriptor: %v", err)
	}
	hexData2 := hex.EncodeToString(data2)

	if !strings.EqualFold(testNtsdHex, hexData2) {
		t.Errorf("Involution failed: Output of ntsd2.Marshal() is not equal to input hex string")
	}
}

func TestNtSecurityDescriptor_Unmarshal(t *testing.T) {
	ntsd := securitydescriptor.NtSecurityDescriptor{}
	ntsd.Header.Revision = 1
	ntsd.Header.Control.AddControl(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_PD)
	ntsd.Header.Control.AddControl(securitydescriptor.NT_SECURITY_DESCRIPTOR_CONTROL_OD)

	ntsd.Owner.SID.FromString("S-1-5-32-544")
	ntsd.Group.SID.FromString("S-1-5-32-544")

	ntsd.DACL.Header.Revision.SetRevision(acl.ACL_REVISION_DS)

	a := ace.AccessControlEntry{}
	a.Index = 0
	a.Header.Type.Value = ace.ACE_TYPE_ACCESS_ALLOWED

	//  (DELETE|DS_CONTROL_ACCESS|DS_CREATE_CHILD|DS_DELETE_CHILD|DS_DELETE_TREE|DS_LIST_CONTENTS|DS_LIST_OBJECT|DS_READ_PROPERTY|DS_WRITE_PROPERTY|DS_WRITE_PROPERTY_EXTENDED|READ_CONTROL|WRITE_DAC|WRITE_OWNER)
	a.Mask.SetRights([]uint32{
		rights.RIGHT_DELETE,
		rights.RIGHT_DS_CONTROL_ACCESS,
		rights.RIGHT_DS_CREATE_CHILD,
		rights.RIGHT_DS_DELETE_CHILD,
		rights.RIGHT_DS_DELETE_TREE,
		rights.RIGHT_DS_LIST_CONTENTS,
		rights.RIGHT_DS_LIST_OBJECT,
		rights.RIGHT_DS_READ_PROPERTY,
		rights.RIGHT_DS_WRITE_PROPERTY,
		rights.RIGHT_DS_WRITE_PROPERTY_EXTENDED,
		rights.RIGHT_READ_CONTROL,
		rights.RIGHT_WRITE_DAC,
		rights.RIGHT_WRITE_OWNER,
	})
	a.SID.SID.FromString("S-1-5-21-2919671431-737980799-3592259605-1112")
	ntsd.DACL.AddEntry(a)

	binaryNTSecurityDescriptor, err := ntsd.Marshal()
	if err != nil {
		t.Errorf("error marshalling NTSecurityDescriptor: %s", err)
	}

	ntsd.Describe(0)

	ntsd2 := &securitydescriptor.NtSecurityDescriptor{}
	_, err = ntsd2.Unmarshal(binaryNTSecurityDescriptor)
	if err != nil {
		t.Errorf("error unmarshalling NTSecurityDescriptor: %s", err)
	}
}
