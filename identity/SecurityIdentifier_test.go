package identity

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func Test_SID_Involution(t *testing.T) {
	testSIDsinHexFormat := []string{
		"01050000000000051500000028bb82279261b9fe2474aa5d00020000",
		// "01050000000000051500000028bb82279261b9fe2030303000000000",
		// // "01050000000000051500000028bb82279261b9fe20", // Seems broken
		// "01020000000000052000000020020000",
		// // Padding tests
		// "01050000000000051500000028bb82279261b9fe2000000000000000",
		// "01050000000000051500000028bb82279261b9fe20000000000000",
		// "01050000000000051500000028bb82279261b9fe200000000000",
		// "01050000000000051500000028bb82279261b9fe2000000000",
		// "01050000000000051500000028bb82279261b9fe20000000",
		// "01050000000000051500000028bb82279261b9fe200000",
		// "01050000000000051500000028bb82279261b9fe2000",
		// "01050000000000051500000028bb82279261b9fe20",
	}
	for _, hexData := range testSIDsinHexFormat {

		rawBytes, err := hex.DecodeString(hexData)
		if err != nil {
			t.Fatalf("Failed to decode hex string: %v", err)
		}

		var sid SID
		_, err = sid.Unmarshal(rawBytes)
		if err != nil {
			t.Fatalf("Failed to unmarshal SID: %v", err)
		}
		serializedBytes, err := sid.Marshal()
		if err != nil {
			t.Fatalf("Failed to marshal SID: %v", err)
		}

		if !bytes.Equal(rawBytes, serializedBytes) {
			fmt.Printf("hexData: %s\n", hexData)
			fmt.Printf("-->: %s\n", sid.ToString())
			sid.Describe(0)

			hexData2 := hex.EncodeToString(serializedBytes)
			minLen := len(hexData2)
			if len(hexData) < minLen {
				minLen = len(hexData)
			}
			for k := 0; k < minLen; k++ {
				if hexData[k] == hexData2[k] {
					hexData = hexData[:k] + "_" + hexData[k+1:]
					hexData2 = hexData2[:k] + "_" + hexData2[k+1:]
				}
			}

			fmt.Println("source-----:", hexData)
			fmt.Println("serialized-:", hexData2)

			t.Errorf("Involution test failed: expected %s, got %s", hex.EncodeToString(rawBytes), hex.EncodeToString(serializedBytes))
		}
	}
}

func Test_SID_LookupName(t *testing.T) {
	sid := &SID{}
	sidString := "S-1-5-32-544"
	sid.FromString(sidString)
	expectedName := "BUILTIN\\Administrators"
	actualName := sid.LookupName()
	if actualName != expectedName {
		t.Errorf("LookupName() failed: expected %s, got %s", expectedName, actualName)
	}
}

func Test_SID_Marshal(t *testing.T) {
	sid := &SID{}
	sidString := "S-1-5-32-544"
	sid.FromString(sidString)
	expectedBytes, _ := hex.DecodeString("01020000000000052000000020020000")
	actualBytes, err := sid.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal SID: %v", err)
	}
	if !strings.EqualFold(hex.EncodeToString(actualBytes), hex.EncodeToString(expectedBytes)) {
		t.Errorf("Marshal() failed: expected %x, got %x", expectedBytes, actualBytes)
	}
}

func Test_SID_FromStringMarshal(t *testing.T) {
	sid := &SID{}
	sidString := "S-1-5-32-544"
	sid.FromString(sidString)
	expectedBytes, _ := hex.DecodeString("01020000000000052000000020020000")
	actualBytes, err := sid.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal SID: %v", err)
	}
	if !bytes.Equal(actualBytes, expectedBytes) {
		t.Errorf("Marshal() failed: expected %x, got %x", expectedBytes, actualBytes)
	}
}

func Test_SID_UnmarshalToString(t *testing.T) {
	sid := &SID{}
	rawBytes, _ := hex.DecodeString("01020000000000052000000020020000")
	_, err := sid.Unmarshal(rawBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal SID: %v", err)
	}
	expectedString := "S-1-5-32-544"
	actualString := sid.ToString()
	if actualString != expectedString {
		t.Errorf("Unmarshal() failed: expected %s, got %s", expectedString, actualString)
	}
}

func Test_SID_InvolutionFromStringToString(t *testing.T) {
	values := []string{
		"S-1-0-0",
		"S-1-1-0",
		"S-1-2-0",
		"S-1-3-0",
		"S-1-3-1",
		"S-1-3-2",
		"S-1-3-3",
		"S-1-3-4",
		"S-1-3-5",
		"S-1-4-0",
		"S-1-5-0",
		"S-1-5-1",
		"S-1-5-2",
		"S-1-5-3",
		"S-1-5-4",
		"S-1-5-6",
		"S-1-5-7",
		"S-1-5-8",
		"S-1-5-9",
		"S-1-5-10",
		"S-1-5-11",
		"S-1-5-12",
		"S-1-5-13",
		"S-1-5-14",
		"S-1-5-15",
		"S-1-5-17",
		"S-1-5-18",
		"S-1-5-19",
		"S-1-5-20",
		"S-1-5-21-3623811015-3361044348-30300820-500",
		"S-1-5-21-3623811015-3361044348-30300820-501",
		"S-1-5-21-3623811015-3361044348-30300820-502",
		"S-1-5-21-3623811015-3361044348-30300820-512",
		"S-1-5-21-3623811015-3361044348-30300820-513",
		"S-1-5-21-3623811015-3361044348-30300820-1000",
		"S-1-5-21-3623811015-3361044348-30300820-1001",
		"S-1-5-21-3623811015-3361044348-30300820-1002",
		"S-1-5-21-3623811015-3361044348-30300820-1101",
		"S-1-5-21-3623811015-3361044348-30300820-2000",
		"S-1-5-21-3623811015-3361044348-30300820-3000",
		"S-1-5-32-544",
		"S-1-5-32-545",
		"S-1-5-32-546",
		"S-1-5-32-547",
		"S-1-5-32-548",
		"S-1-5-32-549",
		"S-1-5-32-550",
		"S-1-5-32-551",
		"S-1-5-32-552",
		"S-1-5-32-554",
		"S-1-5-32-555",
		"S-1-5-32-556",
		"S-1-5-32-557",
		"S-1-5-32-558",
		"S-1-5-32-559",
		"S-1-5-32-560",
		"S-1-5-32-561",
		"S-1-5-32-562",
		"S-1-5-32-569",
		"S-1-5-32-573",
		"S-1-5-33",
		"S-1-5-64-10",
		"S-1-5-64-14",
		"S-1-5-64-21",
		"S-1-5-64-32",
		"S-1-5-80-0",
		"S-1-5-80-123456789-987654321-135792468-246813579-101010101",
		"S-1-5-80-123-456-789-101-112",
		"S-1-5-83-0",
		"S-1-5-96-0",
		"S-1-16-0",
		"S-1-16-4096",
		"S-1-16-8192",
		"S-1-16-8448",
		"S-1-16-12288",
		"S-1-16-16384",
		"S-1-16-20480",
		"S-1-16-28672",
		"S-1-16-30720",
		"S-1-16-32768",
		"S-1-16-40960",
		"S-1-16-49152",
	}
	for _, sidString := range values {
		sid := &SID{}
		sid.FromString(sidString)

		actualString := sid.ToString()

		if actualString != sidString {
			fmt.Printf("[debug] Input: %s\n", sidString)
			sid.Describe(0)

			t.Errorf("ToString() failed: expected %s, got %s", sidString, actualString)
		}
	}
}

func Test_SID_FromStringMarshalToString(t *testing.T) {
	values := []string{
		"S-1-0-0",
		"S-1-1-0",
		"S-1-2-0",
		"S-1-3-0",
		"S-1-3-1",
		"S-1-3-2",
		"S-1-3-3",
		"S-1-3-4",
		"S-1-3-5",
		"S-1-4-0",
		"S-1-5-0",
		"S-1-5-1",
		"S-1-5-2",
		"S-1-5-3",
		"S-1-5-4",
		"S-1-5-6",
		"S-1-5-7",
		"S-1-5-8",
		"S-1-5-9",
		"S-1-5-10",
		"S-1-5-11",
		"S-1-5-12",
		"S-1-5-13",
		"S-1-5-14",
		"S-1-5-15",
		"S-1-5-17",
		"S-1-5-18",
		"S-1-5-19",
		"S-1-5-20",
		"S-1-5-21-3623811015-3361044348-30300820-500",
		"S-1-5-21-3623811015-3361044348-30300820-501",
		"S-1-5-21-3623811015-3361044348-30300820-502",
		"S-1-5-21-3623811015-3361044348-30300820-512",
		"S-1-5-21-3623811015-3361044348-30300820-513",
		"S-1-5-21-3623811015-3361044348-30300820-1000",
		"S-1-5-21-3623811015-3361044348-30300820-1001",
		"S-1-5-21-3623811015-3361044348-30300820-1002",
		"S-1-5-21-3623811015-3361044348-30300820-1101",
		"S-1-5-21-3623811015-3361044348-30300820-2000",
		"S-1-5-21-3623811015-3361044348-30300820-3000",
		"S-1-5-32-544",
		"S-1-5-32-545",
		"S-1-5-32-546",
		"S-1-5-32-547",
		"S-1-5-32-548",
		"S-1-5-32-549",
		"S-1-5-32-550",
		"S-1-5-32-551",
		"S-1-5-32-552",
		"S-1-5-32-554",
		"S-1-5-32-555",
		"S-1-5-32-556",
		"S-1-5-32-557",
		"S-1-5-32-558",
		"S-1-5-32-559",
		"S-1-5-32-560",
		"S-1-5-32-561",
		"S-1-5-32-562",
		"S-1-5-32-569",
		"S-1-5-32-573",
		"S-1-5-33",
		"S-1-5-64-10",
		"S-1-5-64-14",
		"S-1-5-64-21",
		"S-1-5-64-32",
		"S-1-5-80-0",
		"S-1-5-80-123456789-987654321-135792468-246813579-101010101",
		"S-1-5-80-123-456-789-101-112",
		"S-1-5-83-0",
		"S-1-5-96-0",
		"S-1-16-0",
		"S-1-16-4096",
		"S-1-16-8192",
		"S-1-16-8448",
		"S-1-16-12288",
		"S-1-16-16384",
		"S-1-16-20480",
		"S-1-16-28672",
		"S-1-16-30720",
		"S-1-16-32768",
		"S-1-16-40960",
		"S-1-16-49152",
	}
	for _, sidString := range values {
		t.Run(sidString, func(t *testing.T) {
			sid := &SID{}
			sid.FromString(sidString)
			serializedBytes, err := sid.Marshal()
			if err != nil {
				t.Fatalf("Failed to marshal SID: %v", err)
			}

			sid2 := &SID{}
			_, err = sid2.Unmarshal(serializedBytes)
			if err != nil {
				t.Fatalf("Failed to unmarshal SID: %v", err)
			}
			actualString := sid2.ToString()

			if actualString != sidString {
				sid2.Describe(0)
				t.Errorf("ToString() failed: expected %s, got %s", sidString, actualString)
			}
		})
	}
}

func Test_SID_ToString(t *testing.T) {
	sid := &SID{
		RevisionLevel: 1,
		IdentifierAuthority: SecurityIdentifierAuthority{
			Value: 16,
		},
		SubAuthorities:     []uint32{},
		RelativeIdentifier: 49152,
	}
	if sid.ToString() != "S-1-16-49152" {
		t.Errorf("ToString() failed: expected %s, got %s", "S-1-16-49152", sid.ToString())
	}
}
