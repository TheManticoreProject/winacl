package securitydescriptor_test

import (
	"bytes"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/ace"
	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/acl/revision"
	"github.com/TheManticoreProject/winacl/rights"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
	"github.com/TheManticoreProject/winacl/securitydescriptor/control"
)

//go:embed tests/datasets
var datasetFiles embed.FS

func TestNtSecurityDescriptor_Involution(t *testing.T) {
	type descriptorEntry struct {
		Name    string `json:"name"`
		Hexdata string `json:"hexdata"`
	}

	// List dataset folders (e.g. "tests/datasets/Windows 10 - 10.0.19041")
	root := "tests/datasets"
	dirEntries, err := fs.ReadDir(datasetFiles, root)
	if err != nil {
		t.Fatalf("listing datasets root: %v", err)
	}
	var datasetDirs []fs.DirEntry
	for _, e := range dirEntries {
		if e.IsDir() {
			datasetDirs = append(datasetDirs, e)
		}
	}
	if len(datasetDirs) == 0 {
		t.Fatal("no dataset folders found in tests/datasets")
	}

	for _, dirEntry := range datasetDirs {
		datasetName := dirEntry.Name()
		folderPath := root + "/" + datasetName

		// List JSON files in this folder (one per component)
		fileEntries, err := fs.ReadDir(datasetFiles, folderPath)
		if err != nil {
			t.Fatalf("listing folder %s: %v", folderPath, err)
		}

		for _, fileEntry := range fileEntries {
			if fileEntry.IsDir() || !strings.HasSuffix(fileEntry.Name(), ".json") {
				continue
			}
			componentName := strings.TrimSuffix(fileEntry.Name(), ".json")
			filePath := folderPath + "/" + fileEntry.Name()

			data, err := fs.ReadFile(datasetFiles, filePath)
			if err != nil {
				t.Fatalf("reading %s: %v", filePath, err)
			}
			// Strip UTF-8 BOM if present (e.g. from Windows-saved JSON)
			data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

			// Each file is an object with one or more keys -> []descriptorEntry (e.g. {"ActiveDirectory": [...]} or {"Metadata":..., "LocalFileSystem": [...]})
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatalf("parsing %s: %v", filePath, err)
			}
			var descriptors []descriptorEntry
			for _, v := range raw {
				var candidate []descriptorEntry
				if err := json.Unmarshal(v, &candidate); err == nil && len(candidate) > 0 {
					descriptors = candidate
					break
				}
			}
			if descriptors == nil {
				continue
			}

			for _, tt := range descriptors {
				tt := tt
				t.Run(datasetName+"/"+componentName+"/"+tt.Name, func(t *testing.T) {
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
					},
				)
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
