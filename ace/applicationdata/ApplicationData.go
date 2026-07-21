// Package applicationdata models the optional, variable-length ApplicationData
// member that trails the fixed fields of certain ACE types (MS-DTYP 2.4.4.x).
//
// The bytes it holds are interpreted according to the owning ACE type:
//
//   - Callback ACE types (ACCESS_ALLOWED_CALLBACK, ACCESS_DENIED_CALLBACK and
//     their object/audit variants) carry a conditional expression, prefixed by
//     the ACE_CONDITION_SIGNATURE "artx" (MS-DTYP 2.4.4.17.1).
//   - SYSTEM_RESOURCE_ATTRIBUTE ACEs carry a
//     CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structure (MS-DTYP 2.4.10.1).
//   - SYSTEM_SCOPED_POLICY_ID and any other type carry opaque data preserved
//     verbatim.
//
// The raw bytes are always kept intact so that Marshal(Unmarshal(x)) == x; the
// decoded views (conditional expression, resource attribute) are derived on
// demand and never replace the raw bytes.
package applicationdata

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/TheManticoreProject/winacl/ace/acetype"
	"github.com/TheManticoreProject/winacl/ace/condition"
	"github.com/TheManticoreProject/winacl/ace/resourceattribute"
	"github.com/TheManticoreProject/winacl/utils/describe"
)

// ApplicationData holds the trailing ApplicationData bytes of an ACE together
// with the type of the ACE that owns them, which determines how they are
// interpreted when described or serialized to SDDL.
type ApplicationData struct {
	// AceType is the ACE_TYPE value of the owning ACE. It selects how RawBytes
	// are interpreted (conditional expression, resource attribute, ...).
	AceType uint8

	// RawBytes is the verbatim ApplicationData payload.
	RawBytes []byte

	// RawBytesSize is the number of bytes held in RawBytes.
	RawBytesSize uint32
}

// Unmarshal stores the supplied bytes as the ApplicationData payload. The length
// of an ACE's ApplicationData is implied by the ACE Header.Size, so the caller
// passes exactly the trailing bytes that follow the fixed ACE fields. A copy is
// kept so the payload does not alias the caller's buffer.
//
// Parameters:
//   - marshalledData ([]byte): The trailing ApplicationData bytes of an ACE.
//
// Returns:
//   - int: The number of bytes consumed (the full length of marshalledData).
//   - error: Always nil; the signature matches the other ACE sub-structures.
func (ad *ApplicationData) Unmarshal(marshalledData []byte) (int, error) {
	ad.RawBytes = make([]byte, len(marshalledData))
	copy(ad.RawBytes, marshalledData)
	ad.RawBytesSize = uint32(len(ad.RawBytes))

	return len(marshalledData), nil
}

// Marshal serializes the ApplicationData into a byte slice.
//
// Returns:
//   - []byte: The verbatim ApplicationData payload.
//   - error: Always nil; the signature matches the other ACE sub-structures.
func (ad *ApplicationData) Marshal() ([]byte, error) {
	out := make([]byte, len(ad.RawBytes))
	copy(out, ad.RawBytes)

	return out, nil
}

// Len returns the number of bytes held in the ApplicationData payload.
func (ad *ApplicationData) Len() int {
	return len(ad.RawBytes)
}

// IsConditional reports whether the payload carries a conditional expression,
// i.e. whether it begins with the ACE_CONDITION_SIGNATURE ("artx").
func (ad *ApplicationData) IsConditional() bool {
	return condition.IsConditional(ad.RawBytes)
}

// IsResourceAttribute reports whether the payload should be interpreted as a
// resource attribute, which is decided by the owning ACE type.
func (ad *ApplicationData) IsResourceAttribute() bool {
	return ad.AceType == acetype.ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE && len(ad.RawBytes) > 0
}

// ConditionalExpression decodes the payload into its SDDL conditional-expression
// text (without an outer pair of parentheses).
func (ad *ApplicationData) ConditionalExpression() (string, error) {
	return condition.Unmarshal(ad.RawBytes)
}

// ResourceAttribute decodes the payload into its SDDL attribute-data text
// (without an outer pair of parentheses).
func (ad *ApplicationData) ResourceAttribute() (string, error) {
	return resourceattribute.Unmarshal(ad.RawBytes)
}

// Equal reports whether two ApplicationData payloads hold the same bytes.
// bytes.Equal treats a nil and an empty slice as equal, which is the desired
// behavior here.
//
// Parameters:
//   - other (*ApplicationData): The ApplicationData to compare against.
//
// Returns:
//   - bool: true if the payloads are byte-for-byte equal.
func (ad *ApplicationData) Equal(other *ApplicationData) bool {
	if ad == nil || other == nil {
		return ad == other
	}

	return bytes.Equal(ad.RawBytes, other.RawBytes)
}

// DescribeList returns the ApplicationData description as a list of lines at
// indentation depth 0. For a callback ACE carrying a conditional expression it
// shows the ACE_CONDITION signature ("artx") magic bytes and the decoded
// expression; for a resource-attribute ACE it shows the decoded CLAIM
// attribute; otherwise it falls back to the raw bytes. The raw bytes are always
// shown so nothing is hidden if decoding is partial.
func (ad *ApplicationData) DescribeList() []string {
	rawHex := hex.EncodeToString(ad.RawBytes)

	lines := []string{"<ApplicationData>"}

	switch {
	case ad.IsConditional():
		sig := ad.RawBytes[:4]
		lines = append(lines, " │ \x1b[93mType\x1b[0m      : \x1b[94mConditional Expression\x1b[0m")
		lines = append(lines, fmt.Sprintf(" │ \x1b[93mSignature\x1b[0m : \x1b[96m0x%s\x1b[0m (\x1b[94m%s\x1b[0m)", hex.EncodeToString(sig), string(sig)))
		if expr, err := ad.ConditionalExpression(); err == nil {
			lines = append(lines, fmt.Sprintf(" │ \x1b[93mCondition\x1b[0m : \x1b[96m(%s)\x1b[0m", expr))
		} else {
			lines = append(lines, fmt.Sprintf(" │ \x1b[93mCondition\x1b[0m : \x1b[91m<unparsed: %s>\x1b[0m", err))
		}
		lines = append(lines, fmt.Sprintf(" │ \x1b[93mRawBytes\x1b[0m  : \x1b[96m%s\x1b[0m", rawHex))

	case ad.IsResourceAttribute():
		lines = append(lines, " │ \x1b[93mType\x1b[0m      : \x1b[94mResource Attribute (CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1)\x1b[0m")
		if attr, err := ad.ResourceAttribute(); err == nil {
			lines = append(lines, fmt.Sprintf(" │ \x1b[93mAttribute\x1b[0m : \x1b[96m(%s)\x1b[0m", attr))
		} else {
			lines = append(lines, fmt.Sprintf(" │ \x1b[93mAttribute\x1b[0m : \x1b[91m<unparsed: %s>\x1b[0m", err))
		}
		lines = append(lines, fmt.Sprintf(" │ \x1b[93mRawBytes\x1b[0m  : \x1b[96m%s\x1b[0m", rawHex))

	default:
		lines = append(lines, fmt.Sprintf(" │ \x1b[93mRawBytes\x1b[0m : \x1b[96m%s\x1b[0m", rawHex))
	}

	lines = append(lines, " └─")

	return lines
}

// DescribeWithCallback renders the ApplicationData at the given indentation
// depth, routing each line to the provided fmt.Printf-like callback.
func (ad *ApplicationData) DescribeWithCallback(indent int, printf describe.Printf) {
	describe.WithCallback(indent, ad.DescribeList(), printf)
}

func (ad *ApplicationData) Describe(indent int) {
	ad.DescribeWithCallback(indent, fmt.Printf)
}
