package sddl_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/sddl"
)

func TestSDDLtoNtSecurityDescriptor(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		wantDACL  int
		wantSACL  int
		wantOwner string
		wantGroup string
	}{
		{
			name:      "Basic with owner and group",
			input:     "O:BAG:SY",
			wantOwner: "S-1-5-32-544",
			wantGroup: "S-1-5-18",
		},
		{
			name:      "With DACL",
			input:     "O:BAG:BAD:(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)",
			wantOwner: "S-1-5-32-544",
			wantGroup: "S-1-5-32-544",
			wantDACL:  2,
		},
		{
			name:     "With SACL",
			input:    "S:(AU;SAFA;GA;;;WD)",
			wantSACL: 1,
		},
		{
			name:  "Invalid ACE type",
			input: "D:(ZZ;;GA;;;WD)",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ntsd, err := sddl.SDDLtoNtSecurityDescriptor(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SDDLtoNtSecurityDescriptor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if tt.wantOwner != "" && (ntsd.Owner == nil || ntsd.Owner.SID.ToString() != tt.wantOwner) {
				got := ""
				if ntsd.Owner != nil {
					got = ntsd.Owner.SID.ToString()
				}
				t.Errorf("Owner = %s, want %s", got, tt.wantOwner)
			}

			if tt.wantGroup != "" && (ntsd.Group == nil || ntsd.Group.SID.ToString() != tt.wantGroup) {
				got := ""
				if ntsd.Group != nil {
					got = ntsd.Group.SID.ToString()
				}
				t.Errorf("Group = %s, want %s", got, tt.wantGroup)
			}

			if tt.wantDACL > 0 {
				if ntsd.DACL == nil || len(ntsd.DACL.Entries) != tt.wantDACL {
					got := 0
					if ntsd.DACL != nil {
						got = len(ntsd.DACL.Entries)
					}
					t.Errorf("DACL entries = %d, want %d", got, tt.wantDACL)
				}
			}

			if tt.wantSACL > 0 {
				if ntsd.SACL == nil || len(ntsd.SACL.Entries) != tt.wantSACL {
					got := 0
					if ntsd.SACL != nil {
						got = len(ntsd.SACL.Entries)
					}
					t.Errorf("SACL entries = %d, want %d", got, tt.wantSACL)
				}
			}
		})
	}
}

func TestNtSecurityDescriptortoSDDL(t *testing.T) {
	input := "O:BAG:SYD:(A;CIOI;GA;;;BA)S:(AU;SAFA;GA;;;WD)"
	ntsd, err := sddl.SDDLtoNtSecurityDescriptor(input)
	if err != nil {
		t.Fatalf("SDDLtoNtSecurityDescriptor() error = %v", err)
	}

	output, err := sddl.NtSecurityDescriptortoSDDL(ntsd)
	if err != nil {
		t.Fatalf("NtSecurityDescriptortoSDDL() error = %v", err)
	}

	if output != input {
		t.Errorf("Round-trip:\n  input:  %s\n  output: %s", input, output)
	}
}
