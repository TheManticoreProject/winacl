package ace

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

// TestAccessControlEntry_Involution_ACE_TYPE_ACCESS_ALLOWED tests the involution property of the AccessControlEntry's Marshal and Unmarshal methods.
func TestAccessControlEntry_Involution_ACE_TYPE_ACCESS_ALLOWED(t *testing.T) {
	hexData := []string{
		"00002400ff010f0001050000000000051500000028bb82279261b9fe2474aa5d00020000",
		"0240140020000c00010100000000000100000000",
		"075a38002000000003000000be3b0ef3f09fd111b6030000f80367c1a57a96bfe60dd011a28500aa003049e2010100000000000100000000",
		"075a38002000000003000000bf3b0ef3f09fd111b6030000f80367c1a57a96bfe60dd011a28500aa003049e2010100000000000100000000",
	}
	for _, hexData := range hexData {
		rawBytes, err := hex.DecodeString(hexData)
		if err != nil {
			t.Fatalf("Failed to decode hex string: %v", err)
		}

		var ace AccessControlEntry
		_, err = ace.Unmarshal(rawBytes)
		if err != nil {
			t.Fatalf("Failed to unmarshal AccessControlEntry: %v", err)
		}

		serializedBytes, err := ace.Marshal()
		if err != nil {
			t.Fatalf("Failed to marshal AccessControlEntry: %v", err)
		}

		if !bytes.Equal(rawBytes, serializedBytes) {
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
