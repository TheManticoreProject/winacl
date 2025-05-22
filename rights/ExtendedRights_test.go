package rights

import (
	"testing"
)

func TestExtendedRights(t *testing.T) {
	testCases := []struct {
		name     string
		constant string
		expected string
	}{
		{
			name:     "EXTENDED_RIGHT_ABANDON_REPLICATION",
			constant: EXTENDED_RIGHT_ABANDON_REPLICATION,
			expected: "ee914b82-0a98-11d1-adbb-00c04fd8d5cd",
		},
		{
			name:     "EXTENDED_RIGHT_ADD_GUID",
			constant: EXTENDED_RIGHT_ADD_GUID,
			expected: "440820ad-65b4-11d1-a3da-0000f875ae0d",
		},
		{
			name:     "EXTENDED_RIGHT_USER_CHANGE_PASSWORD",
			constant: EXTENDED_RIGHT_USER_CHANGE_PASSWORD,
			expected: "ab721a53-1e2f-11d0-9819-00aa0040529b",
		},
		{
			name:     "EXTENDED_RIGHT_USER_FORCE_CHANGE_PASSWORD",
			constant: EXTENDED_RIGHT_USER_FORCE_CHANGE_PASSWORD,
			expected: "00299570-246d-11d0-a768-00aa006e0529",
		},
		{
			name:     "EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES",
			constant: EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES,
			expected: "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
		},
		{
			name:     "EXTENDED_RIGHT_DS_REPLICATION_SYNCHRONIZE",
			constant: EXTENDED_RIGHT_DS_REPLICATION_SYNCHRONIZE,
			expected: "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2",
		},
		{
			name:     "EXTENDED_RIGHT_REANIMATE_TOMBSTONES",
			constant: EXTENDED_RIGHT_REANIMATE_TOMBSTONES,
			expected: "45ec5156-db7e-47bb-b53f-dbeb2d03c40f",
		},
		{
			name:     "EXTENDED_RIGHT_RECEIVE_AS",
			constant: EXTENDED_RIGHT_RECEIVE_AS,
			expected: "ab721a56-1e2f-11d0-9819-00aa0040529b",
		},
		{
			name:     "EXTENDED_RIGHT_SEND_AS",
			constant: EXTENDED_RIGHT_SEND_AS,
			expected: "ab721a54-1e2f-11d0-9819-00aa0040529b",
		},
		{
			name:     "EXTENDED_RIGHT_DS_CLONE_DOMAIN_CONTROLLER",
			constant: EXTENDED_RIGHT_DS_CLONE_DOMAIN_CONTROLLER,
			expected: "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.constant != tc.expected {
				t.Errorf("Expected %s to be %s, got %s", tc.name, tc.expected, tc.constant)
			}
		})
	}
}
