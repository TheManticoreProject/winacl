package identity_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/identity"
	"github.com/TheManticoreProject/winacl/sid"
	"github.com/TheManticoreProject/winacl/sid/authority"
)

func TestIdentity_MarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		identity identity.Identity
	}{
		{
			name: "Basic SID",
			identity: identity.Identity{
				Name: "Test User",
				SID: sid.SID{
					RevisionLevel:       1,
					SubAuthorityCount:   1,
					IdentifierAuthority: authority.SecurityIdentifierAuthority{Value: 5},
					SubAuthorities:      []uint32{},
					RelativeIdentifier:  21,
				},
			},
		},
		{
			name: "Well Known SID",
			identity: identity.Identity{
				SID: sid.SID{
					RevisionLevel:       1,
					SubAuthorityCount:   1,
					IdentifierAuthority: authority.SecurityIdentifierAuthority{Value: 1},
					SubAuthorities:      []uint32{},
					RelativeIdentifier:  0,
				},
			},
		},
		{
			name: "Complex SID",
			identity: identity.Identity{
				Name: "Domain User",
				SID: sid.SID{
					RevisionLevel:       1,
					SubAuthorityCount:   4,
					IdentifierAuthority: authority.SecurityIdentifierAuthority{Value: 5},
					SubAuthorities:      []uint32{21, 2644, 2355},
					RelativeIdentifier:  1234,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			marshalledData, err := tt.identity.Marshal()
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}

			// Unmarshal into new Identity
			var newIdentity identity.Identity
			bytesRead, err := newIdentity.Unmarshal(marshalledData)
			if err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			// Check bytes read matches marshalled data length
			if bytesRead != len(marshalledData) {
				t.Errorf("Unmarshal() bytesRead = %v, want %v", bytesRead, len(marshalledData))
			}

			// Compare SIDs
			if !tt.identity.SID.Equal(&newIdentity.SID) {
				t.Errorf("SIDs do not match after marshal/unmarshal\noriginal: %v\nnew: %v",
					tt.identity.SID.ToString(), newIdentity.SID.ToString())
			}

			// For well-known SIDs, check name was properly assigned
			if _, exists := sid.WellKnownSIDs[tt.identity.SID.ToString()]; exists {
				if newIdentity.Name == "" {
					t.Error("Well-known SID name not assigned during unmarshal")
				}
			}
		})
	}
}
