package securitydescriptor_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

// FuzzNtSecurityDescriptor_Unmarshal asserts that Unmarshal never panics on
// arbitrary input. A parse error is an acceptable outcome; a panic is not.
// Regression test for issue #30.
func FuzzNtSecurityDescriptor_Unmarshal(f *testing.F) {
	seeds := [][]byte{
		nil,
		{},
		{0x01},
		{0x01, 0x00, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Unmarshal panicked on input len=%d: %v", len(data), r)
			}
		}()
		ntsd := securitydescriptor.NtSecurityDescriptor{}
		_, _ = ntsd.Unmarshal(data)
	})
}

// FuzzNtSecurityDescriptor_FromSDDLString asserts that FromSDDLString never
// panics on arbitrary string input.
func FuzzNtSecurityDescriptor_FromSDDLString(f *testing.F) {
	seeds := []string{
		"",
		"O:BAG:SYD:(A;;GA;;;WD)",
		"D:(",
		"S:(AU;SAFA;GA;;;WD",
		"o:bag:syd:(a;;ga;;;wd)",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("FromSDDLString panicked on input %q: %v", data, r)
			}
		}()
		ntsd := securitydescriptor.NtSecurityDescriptor{}
		_, _ = ntsd.FromSDDLString(data)
	})
}
