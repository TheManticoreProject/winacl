package sddl_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/TheManticoreProject/winacl/sddl"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

func TestSddlCut(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantOwner    string
		wantGroup    string
		wantDaclAces []string
		wantSaclAces []string
	}{
		{
			name:      "Basic SDDL with owner and group",
			input:     "O:BAG:BA",
			wantOwner: "BA",
			wantGroup: "BA",
		},
		{
			name:         "SDDL with DACL",
			input:        "O:S-1-5-32-544G:S-1-5-32-545D:AI(A;ID;FA;;;WD)",
			wantOwner:    "S-1-5-32-544",
			wantGroup:    "S-1-5-32-545",
			wantDaclAces: []string{"A;ID;FA;;;WD"},
		},
		{
			name:         "SDDL with multiple ACEs",
			input:        "O:BAG:BAD:(A;OICI;GA;;;BA)(A;OICI;GA;;;SY)",
			wantDaclAces: []string{"A;OICI;GA;;;BA", "A;OICI;GA;;;SY"},
			wantSaclAces: []string{},
			wantOwner:    "BA",
			wantGroup:    "BA",
		},
		{
			name:         "SDDL with SACL",
			input:        "S:AI(AU;SA;FA;;;WD)",
			wantSaclAces: []string{"AU;SA;FA;;;WD"},
		},
		{
			name:         "Complex SDDL with all components",
			input:        "O:S-1-5-32-544G:S-1-5-32-545D:AI(A;ID;FA;;;WD)(A;ID;FA;;;SY)S:AI(AU;SA;FA;;;WD)",
			wantOwner:    "S-1-5-32-544",
			wantGroup:    "S-1-5-32-545",
			wantDaclAces: []string{"A;ID;FA;;;WD", "A;ID;FA;;;SY"},
			wantSaclAces: []string{"AU;SA;FA;;;WD"},
		},
		{
			name:         "Long SDDL with multiple ACEs",
			input:        "O:DAG:DAD:(A;;RPWPCCDCLCRCWOWDSDSW;;;SY)(A;;RPWPCCDCLCRCWOWDSDSW;;;DA)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;6da8a4ff-0e52-11d0-a286-00aa003049e2;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(A;;RPLCRC;;;AU)S:(AU;SAFA;WDWOSDWPCCDCSW;;;WD)",
			wantDaclAces: []string{"A;;RPWPCCDCLCRCWOWDSDSW;;;SY", "A;;RPWPCCDCLCRCWOWDSDSW;;;DA", "OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO", "OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO", "OA;;CCDC;6da8a4ff-0e52-11d0-a286-00aa003049e2;;AO", "OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO", "A;;RPLCRC;;;AU"},
			wantSaclAces: []string{"AU;SAFA;WDWOSDWPCCDCSW;;;WD"},
			wantOwner:    "DA",
			wantGroup:    "DA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOwner, gotGroup, gotDaclAces, gotSaclAces := sddl.CutSDDL(tt.input)

			if gotOwner != tt.wantOwner {
				t.Errorf("CutSDDL() owner = %v, want %v", gotOwner, tt.wantOwner)
			}

			if gotGroup != tt.wantGroup {
				t.Errorf("CutSDDL() group = %v, want %v", gotGroup, tt.wantGroup)
			}

			if len(gotDaclAces) != len(tt.wantDaclAces) {
				t.Errorf("CutSDDL() daclAces = %v, want %v", gotDaclAces, tt.wantDaclAces)
			} else {
				if !slices.Equal(gotDaclAces, tt.wantDaclAces) {
					t.Errorf("CutSDDL() daclAces = %v, want %v", gotDaclAces, tt.wantDaclAces)
					for i := range gotDaclAces {
						if gotDaclAces[i] != tt.wantDaclAces[i] {
							t.Errorf("DACL ACE at index %d differs: got %v, want %v", i, gotDaclAces[i], tt.wantDaclAces[i])
						}
					}
				}
			}

			if len(gotSaclAces) != len(tt.wantSaclAces) {
				t.Errorf("CutSDDL() saclAces = %v, want %v", gotSaclAces, tt.wantSaclAces)
			} else {
				if !slices.Equal(gotSaclAces, tt.wantSaclAces) {
					t.Errorf("CutSDDL() saclAces = %v, want %v", gotSaclAces, tt.wantSaclAces)
					for i := range gotSaclAces {
						if gotSaclAces[i] != tt.wantSaclAces[i] {
							t.Errorf("SACL ACE at index %d differs: got %v, want %v", i, gotSaclAces[i], tt.wantSaclAces[i])
						}
					}
				}
			}
		})
	}
}

func TestSDDLToBinary(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		// Source: 2.5.1.4 SDDL String to Binary Security Descriptor Examples
		// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2918391b-75b9-4eeb-83f0-7fdc04a5c6c9
		{
			name:  "2.5.1.4 SDDL String to Binary Security Descriptor Examples",
			input: "O:BAG:BAD:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)S:P(AU;FA;GR;;;WD)",
			want:  "010014b090000000a0000000140000003000000002001c00010000000280140000000080010100000000000100000000020060000400000000031800000000a001020000000000052000000021020000000318000000001001020000000000052000000020020000000314000000001001010000000000051200000000031400000000100101000000000003000000000102000000000005200000002002000001020000000000052000000020020000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ntsd := securitydescriptor.NtSecurityDescriptor{}
			got, err := ntsd.FromSDDLString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToSecurityDescriptor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				gotHex := fmt.Sprintf("%x", got)
				if gotHex != tt.want {
					t.Errorf("ToSecurityDescriptor() = %v, want %v", gotHex, tt.want)
				}
			}
		})
	}
}
