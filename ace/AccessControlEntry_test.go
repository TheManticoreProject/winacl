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

func TestAccessControlEntry_Size(t *testing.T) {
	hexData := []string{
		"00002400ff010f0001050000000000051500000028bb82279261b9fe2474aa5d00020000",
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
	}
}

// TestAccessControlEntry_Unmarshal_MalformedNoPanic verifies that
// Unmarshalling truncated or otherwise malformed ACE binary data returns a
// parse error instead of panicking. Regression test for issue #30.
func TestAccessControlEntry_Unmarshal_MalformedNoPanic(t *testing.T) {
	cases := []struct {
		name string
		hex  string
	}{
		// Header declares Size=4 (exactly the header) but the ACE type
		// (ACCESS_ALLOWED = 0x00) expects a Mask and SID after it.
		{"access_allowed_size4_no_body", "00000400"},
		// Header Size=8: header + mask, but no SID bytes.
		{"access_allowed_size8_no_sid", "00000800deadbeef"},
		// Object ACE claiming Size=16 with truncated GUID region.
		{"object_ace_truncated", "0500100000000000010000000000000000000000"},
		// Header Size=5: 1 trailing byte — too short for a 4-byte mask.
		{"access_allowed_size5_one_body_byte", "0000050000"},
		// Minimum ACE-type byte only, no header size field.
		{"ace_single_byte", "00"},
		{"ace_two_bytes", "0000"},
		{"ace_three_bytes", "000000"},
		// ACL-level buffer truncation: a DACL iteration delegating here
		// must not crash the process on malformed content.
		{"access_denied_size4", "01000400"},
		{"system_audit_size4", "02000400"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.hex)
			if err != nil {
				t.Fatalf("hex decode: %v", err)
			}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Unmarshal panicked on malformed input %q: %v", tc.hex, r)
				}
			}()
			var a AccessControlEntry
			_, err = a.Unmarshal(raw)
			if err == nil {
				t.Fatalf("expected an error for malformed input %q, got nil", tc.hex)
			}
		})
	}
}
