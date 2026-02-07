package securitydescriptor_test

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/acl/revision"
	"github.com/TheManticoreProject/winacl/rights"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
	"github.com/TheManticoreProject/winacl/securitydescriptor/control"
)

//go:embed tests/datasets/*.json
var datasetFiles embed.FS

func TestNtSecurityDescriptor_Involution(t *testing.T) {
	type descriptorEntry struct {
		Name    string `json:"name"`
		Hexdata string `json:"hexdata"`
	}
	type datasetFile map[string]map[string][]descriptorEntry

	entries, err := fs.Glob(datasetFiles, "tests/datasets/*.json")
	if err != nil {
		t.Fatalf("listing dataset files: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no JSON datasets found in tests/datasets")
	}

	for _, name := range entries {
		data, err := fs.ReadFile(datasetFiles, name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		var testdataset datasetFile
		if err := json.Unmarshal(data, &testdataset); err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		datasetName := strings.TrimSuffix(filepath.Base(name), ".json")

		for environment, byComponent := range testdataset {
			for sourceComponent, descriptors := range byComponent {
				for _, tt := range descriptors {
					tt := tt
					t.Run(datasetName+"/"+environment+"/"+sourceComponent+"/"+tt.Name, func(t *testing.T) {
						hexdata := tt.Hexdata
						ntsd := &securitydescriptor.NtSecurityDescriptor{}
						ntsdBytes, err := hex.DecodeString(hexdata)
						if err != nil {
							t.Errorf("Failed to decode hexdata: %v", err)
							return
						}
						_, err = ntsd.Unmarshal(ntsdBytes)
						if err != nil {
							t.Errorf("Failed to unmarshal NtSecurityDescriptor: %v", err)
							return
						}

						serializedBytes, err := ntsd.Marshal()
						if err != nil {
							t.Errorf("Failed to marshal NtSecurityDescriptor: %v", err)
							return
						}
						hexData1 := hex.EncodeToString(serializedBytes)

						if !strings.EqualFold(hexdata, hexData1) {
							minLen := len(hexData1)
							if len(hexdata) < minLen {
								minLen = len(hexdata)
							}
							hexdataDisp := hexdata
							for k := 0; k < minLen; k++ {
								if hexData1[k] == hexdata[k] {
									hexData1 = hexData1[:k] + "_" + hexData1[k+1:]
									hexdataDisp = hexdataDisp[:k] + "_" + hexdataDisp[k+1:]
								}
							}
							fmt.Println("output-:", hexData1)
							fmt.Println("input--:", hexdataDisp)
							t.Errorf("NtSecurityDescriptor.Marshal() failed: Output of ntsd.Marshal() is not equal to input hex string")
						}

						ntsd2 := &securitydescriptor.NtSecurityDescriptor{}
						_, err = ntsd2.Unmarshal(serializedBytes)
						if err != nil {
							t.Errorf("Failed to unmarshal NtSecurityDescriptor: %v", err)
							return
						}
						data2, err := ntsd2.Marshal()
						if err != nil {
							t.Errorf("Failed to marshal NtSecurityDescriptor: %v", err)
							return
						}
						hexData2 := hex.EncodeToString(data2)

						if !strings.EqualFold(hexdata, hexData2) {
							t.Errorf("Involution failed: Output of ntsd2.Marshal() is not equal to input hex string")
						}
					})
				}
			}
		}
	}
}

func TestNtSecurityDescriptor_Unmarshal(t *testing.T) {
	ntsd := securitydescriptor.NewSecurityDescriptor()

	ntsd.Header.Control.AddControl(control.NT_SECURITY_DESCRIPTOR_CONTROL_PD)
	ntsd.Header.Control.AddControl(control.NT_SECURITY_DESCRIPTOR_CONTROL_OD)

	ntsd.Owner.SID.FromString("S-1-5-32-544")
	ntsd.Group.SID.FromString("S-1-5-32-544")
	ntsd.DACL.Header.Revision.SetRevision(revision.ACL_REVISION_DS)

	a := ace.AccessControlEntry{}
	a.Index = 0
	a.Header.Type.Value = acetype.ACE_TYPE_ACCESS_ALLOWED

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
	a.Identity.SID.FromString("S-1-5-21-2919671431-737980799-3592259605-1112")
	ntsd.DACL.AddEntry(a)

	binaryNTSecurityDescriptor, err := ntsd.Marshal()
	if err != nil {
		t.Errorf("error marshalling NTSecurityDescriptor: %s", err)
	}

	ntsd2 := &securitydescriptor.NtSecurityDescriptor{}
	_, err = ntsd2.Unmarshal(binaryNTSecurityDescriptor)
	if err != nil {
		t.Errorf("error unmarshalling NTSecurityDescriptor: %s", err)
	}
}
