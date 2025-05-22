package object

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestAccessControlObjectType_Involution(t *testing.T) {
	hexData := "03000000be3b0ef3f09fd111b6030000f80367c1a57a96bfe60dd011a28500aa003049e2"
	rawBytes, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}

	var aco AccessControlObjectType
	_, err = aco.Unmarshal(rawBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal AccessControlObjectType: %v", err)
	}

	serializedBytes, err := aco.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal AccessControlObjectType: %v", err)
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

		t.Errorf("Expected byte slice of length %d, but got %d", len(hexData), len(hexData2))
	}
}
