package flags_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/object/flags"
)

// TestAccessControlObjectTypeFlags_Unmarshal_TruncatedReturnsError asserts that
// Unmarshal returns a parse error instead of panicking when fewer than 4 bytes
// are provided. Regression test for issue #30.
func TestAccessControlObjectTypeFlags_Unmarshal_TruncatedReturnsError(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3} {
		buf := make([]byte, n)
		var f flags.AccessControlObjectTypeFlags
		_, err := f.Unmarshal(buf)
		if err == nil {
			t.Errorf("Unmarshal(%d bytes) expected error, got nil", n)
		}
	}
}
