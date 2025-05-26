package sid_test

import (
	"testing"

	"github.com/TheManticoreProject/winacl/sid"
	"github.com/TheManticoreProject/winacl/sid/authority"
)

func TestSecurityIdentifier_Equal(t *testing.T) {
	tests := []struct {
		name     string
		sid1     *sid.SID
		sid2     *sid.SID
		expected bool
	}{
		{
			name: "Equal SIDs",
			sid1: &sid.SID{
				RevisionLevel:       1,
				SubAuthorityCount:   2,
				IdentifierAuthority: authority.SecurityIdentifierAuthority{Value: 5},
				SubAuthorities:      []uint32{32, 544},
				RelativeIdentifier:  1000,
				Reserved:            []byte{0x00, 0x01},
			},
			sid2: &sid.SID{
				RevisionLevel:       1,
				SubAuthorityCount:   2,
				IdentifierAuthority: authority.SecurityIdentifierAuthority{Value: 5},
				SubAuthorities:      []uint32{32, 544},
				RelativeIdentifier:  1000,
				Reserved:            []byte{0x00, 0x01},
			},
			expected: true,
		},
		{
			name: "Different RevisionLevel",
			sid1: &sid.SID{
				RevisionLevel:       1,
				SubAuthorityCount:   2,
				IdentifierAuthority: authority.SecurityIdentifierAuthority{Value: 5},
			},
			sid2: &sid.SID{
				RevisionLevel:       2,
				SubAuthorityCount:   2,
				IdentifierAuthority: authority.SecurityIdentifierAuthority{Value: 5},
			},
			expected: false,
		},
		{
			name: "Different SubAuthorityCount",
			sid1: &sid.SID{
				RevisionLevel:       1,
				SubAuthorityCount:   2,
				IdentifierAuthority: authority.SecurityIdentifierAuthority{Value: 5},
			},
			sid2: &sid.SID{
				RevisionLevel:       1,
				SubAuthorityCount:   3,
				IdentifierAuthority: authority.SecurityIdentifierAuthority{Value: 5},
			},
			expected: false,
		},
		{
			name: "Different IdentifierAuthority",
			sid1: &sid.SID{
				RevisionLevel:       1,
				SubAuthorityCount:   2,
				IdentifierAuthority: authority.SecurityIdentifierAuthority{Value: 5},
			},
			sid2: &sid.SID{
				RevisionLevel:       1,
				SubAuthorityCount:   2,
				IdentifierAuthority: authority.SecurityIdentifierAuthority{Value: 6},
			},
			expected: false,
		},
		{
			name: "Different SubAuthorities",
			sid1: &sid.SID{
				SubAuthorities: []uint32{32, 544},
			},
			sid2: &sid.SID{
				SubAuthorities: []uint32{32, 545},
			},
			expected: false,
		},
		{
			name: "Different RelativeIdentifier",
			sid1: &sid.SID{
				RelativeIdentifier: 1000,
			},
			sid2: &sid.SID{
				RelativeIdentifier: 1001,
			},
			expected: false,
		},
		{
			name: "Different Reserved bytes",
			sid1: &sid.SID{
				Reserved: []byte{0x00, 0x01},
			},
			sid2: &sid.SID{
				Reserved: []byte{0x00, 0x02},
			},
			expected: false,
		},
		{
			name:     "Both nil",
			sid1:     nil,
			sid2:     nil,
			expected: true,
		},
		{
			name:     "First nil",
			sid1:     nil,
			sid2:     &sid.SID{},
			expected: false,
		},
		{
			name:     "Second nil",
			sid1:     &sid.SID{},
			sid2:     nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.sid1.Equal(tt.sid2)
			if result != tt.expected {
				t.Errorf("Equal() = %v, want %v", result, tt.expected)
			}
		})
	}
}
