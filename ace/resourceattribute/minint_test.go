package resourceattribute_test

import (
	"encoding/binary"
	"testing"

	"github.com/TheManticoreProject/winacl/ace/resourceattribute"
)

// TestMinInt64_TI is a regression test for parseIntAuto rejecting the
// most-negative INT64 value. A CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64 (TI) value is
// a signed LONG64 whose range includes -9223372036854775808.
func TestMinInt64_TI(t *testing.T) {
	cases := []struct {
		text string
		want int64
	}{
		{`"n",TI,0,-9223372036854775808`, -9223372036854775808}, // math.MinInt64
		{`"n",TI,0,9223372036854775807`, 9223372036854775807},   // math.MaxInt64
		{`"n",TI,0,-1`, -1},
		{`"n",TI,0,0`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			bin, err := resourceattribute.Marshal(tc.text)
			if err != nil {
				t.Fatalf("Marshal(%q) error = %v", tc.text, err)
			}
			ra, err := resourceattribute.Decode(bin)
			if err != nil {
				t.Fatalf("Decode error = %v", err)
			}
			if len(ra.Ints) != 1 || ra.Ints[0] != tc.want {
				t.Fatalf("decoded Ints = %v, want [%d]", ra.Ints, tc.want)
			}
		})
	}

	// The MinInt64 value must encode as the 8-byte LE 0x0000000000000080.
	bin, err := resourceattribute.Marshal(`"n",TI,0,-9223372036854775808`)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	ra, _ := resourceattribute.Decode(bin)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(ra.Ints[0]))
	if buf != [8]byte{0, 0, 0, 0, 0, 0, 0, 0x80} {
		t.Fatalf("MinInt64 encoded as %x, want 0000000000000080", buf)
	}
}

// TestOverflow_TI verifies values beyond the signed 64-bit range are rejected.
func TestOverflow_TI(t *testing.T) {
	bad := []string{
		`"n",TI,0,9223372036854775808`,  // 2^63, one past MaxInt64
		`"n",TI,0,-9223372036854775809`, // one below MinInt64
	}
	for _, s := range bad {
		if _, err := resourceattribute.Marshal(s); err == nil {
			t.Errorf("Marshal(%q) expected an out-of-range error, got nil", s)
		}
	}
}
