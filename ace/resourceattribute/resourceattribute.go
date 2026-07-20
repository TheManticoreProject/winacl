// Package resourceattribute implements the codec for the resource-attribute
// data carried in a SYSTEM_RESOURCE_ATTRIBUTE_ACE (MS-DTYP 2.4.4.15). The ACE's
// ApplicationData is a CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structure (MS-DTYP
// 2.4.10.1); this package converts between that binary form and the SDDL
// attribute-data text `"name",TYPE,flags,value,...` (MS-DTYP 2.5.1.1).
//
//	text  -> Marshal   -> CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 bytes
//	bytes -> Unmarshal -> text
//
// The structure is offset-based: a fixed 16-byte header (Name, ValueType,
// Reserved, Flags, ValueCount) is followed by an array of ValueCount DWORD
// offsets, each pointing (from the start of the structure) to a value; the
// attribute name and the values themselves follow. All integers are
// little-endian and the whole structure is padded to a DWORD boundary.
package resourceattribute

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	sddl_sid "github.com/TheManticoreProject/winacl/sddl/sid"
	"github.com/TheManticoreProject/winacl/sid"
)

// CLAIM_SECURITY_ATTRIBUTE_TYPE value-type codes (MS-DTYP 2.4.10.1).
const (
	TypeInt64       uint16 = 0x0001
	TypeUint64      uint16 = 0x0002
	TypeString      uint16 = 0x0003
	TypeSID         uint16 = 0x0005
	TypeBoolean     uint16 = 0x0006
	TypeOctetString uint16 = 0x0010
)

// sddlTypeToValueType maps the SDDL resource-attribute data-type code to the
// CLAIM_SECURITY_ATTRIBUTE_TYPE value.
var sddlTypeToValueType = map[string]uint16{
	"TI": TypeInt64,
	"TU": TypeUint64,
	"TS": TypeString,
	"TD": TypeSID,
	"TX": TypeOctetString,
	"TB": TypeBoolean,
}

var valueTypeToSDDLType = map[uint16]string{
	TypeInt64:       "TI",
	TypeUint64:      "TU",
	TypeString:      "TS",
	TypeSID:         "TD",
	TypeOctetString: "TX",
	TypeBoolean:     "TB",
}

// ResourceAttribute is the decoded representation of a resource attribute.
// Exactly one of the value slices is populated, chosen by ValueType.
type ResourceAttribute struct {
	Name      string
	ValueType uint16
	Flags     uint32

	Ints    []int64  // TypeInt64, TypeUint64, TypeBoolean
	Strings []string // TypeString
	SIDs    []string // TypeSID (string form)
	Octets  [][]byte // TypeOctetString
}

const headerLen = 16 // Name(4) + ValueType(2) + Reserved(2) + Flags(4) + ValueCount(4)

// Marshal parses an SDDL attribute-data string (optionally wrapped in a single
// outer pair of parentheses, as it appears in an ACE) and returns the binary
// CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 encoding.
func Marshal(attrData string) ([]byte, error) {
	ra, err := Parse(attrData)
	if err != nil {
		return nil, err
	}
	return ra.Encode()
}

// Unmarshal decodes CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 bytes into the SDDL
// attribute-data text (without an outer pair of parentheses).
func Unmarshal(data []byte) (string, error) {
	ra, err := Decode(data)
	if err != nil {
		return "", err
	}
	return ra.String(), nil
}

// Parse converts SDDL attribute-data text into a ResourceAttribute.
func Parse(attrData string) (*ResourceAttribute, error) {
	s := strings.TrimSpace(attrData)
	// Strip a single enclosing pair of parentheses if present.
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		s = s[1 : len(s)-1]
	}

	fields := splitTopLevelCommas(s)
	if len(fields) < 3 {
		return nil, fmt.Errorf("resource attribute requires at least name, type and flags fields, got %q", attrData)
	}

	name, err := parseQuoted(strings.TrimSpace(fields[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid resource attribute name: %w", err)
	}

	typeStr := strings.TrimSpace(fields[1])
	vt, ok := sddlTypeToValueType[typeStr]
	if !ok {
		return nil, fmt.Errorf("unknown resource attribute type %q", typeStr)
	}

	flags, err := parseUintAuto(strings.TrimSpace(fields[2]))
	if err != nil {
		return nil, fmt.Errorf("invalid resource attribute flags %q: %w", fields[2], err)
	}

	ra := &ResourceAttribute{Name: name, ValueType: vt, Flags: uint32(flags)}

	for _, raw := range fields[3:] {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if err := ra.appendValue(v); err != nil {
			return nil, err
		}
	}
	return ra, nil
}

func (ra *ResourceAttribute) appendValue(v string) error {
	switch ra.ValueType {
	case TypeInt64:
		n, err := parseIntAuto(v)
		if err != nil {
			return fmt.Errorf("invalid TI value %q: %w", v, err)
		}
		ra.Ints = append(ra.Ints, n)
	case TypeUint64:
		n, err := parseUintAuto(v)
		if err != nil {
			return fmt.Errorf("invalid TU value %q: %w", v, err)
		}
		ra.Ints = append(ra.Ints, int64(n))
	case TypeBoolean:
		switch v {
		case "0":
			ra.Ints = append(ra.Ints, 0)
		case "1":
			ra.Ints = append(ra.Ints, 1)
		default:
			return fmt.Errorf("invalid TB value %q (must be 0 or 1)", v)
		}
	case TypeString:
		s, err := parseQuoted(v)
		if err != nil {
			return fmt.Errorf("invalid TS value %q: %w", v, err)
		}
		ra.Strings = append(ra.Strings, s)
	case TypeSID:
		ra.SIDs = append(ra.SIDs, v)
	case TypeOctetString:
		b, err := parseOctet(v)
		if err != nil {
			return fmt.Errorf("invalid TX value %q: %w", v, err)
		}
		ra.Octets = append(ra.Octets, b)
	}
	return nil
}

// Encode serializes the ResourceAttribute into binary form.
func (ra *ResourceAttribute) Encode() ([]byte, error) {
	// Build the value blobs first so we can lay out offsets.
	valueBlobs, err := ra.encodeValues()
	if err != nil {
		return nil, err
	}
	count := len(valueBlobs)

	nameBytes := encodeUTF16NUL(ra.Name)

	out := make([]byte, headerLen+4*count)
	// Layout: header, offset array, name, values.
	cursor := headerLen + 4*count

	nameOffset := cursor
	out = append(out, nameBytes...)
	cursor += len(nameBytes)

	valueOffsets := make([]int, count)
	for i, blob := range valueBlobs {
		valueOffsets[i] = cursor
		out = append(out, blob...)
		cursor += len(blob)
	}

	// Header.
	binary.LittleEndian.PutUint32(out[0:4], uint32(nameOffset))
	binary.LittleEndian.PutUint16(out[4:6], ra.ValueType)
	binary.LittleEndian.PutUint16(out[6:8], 0) // Reserved
	binary.LittleEndian.PutUint32(out[8:12], ra.Flags)
	binary.LittleEndian.PutUint32(out[12:16], uint32(count))

	// Offset array.
	for i, off := range valueOffsets {
		binary.LittleEndian.PutUint32(out[headerLen+4*i:headerLen+4*i+4], uint32(off))
	}

	// Pad to a DWORD boundary.
	for len(out)%4 != 0 {
		out = append(out, 0x00)
	}
	return out, nil
}

func (ra *ResourceAttribute) encodeValues() ([][]byte, error) {
	var blobs [][]byte
	switch ra.ValueType {
	case TypeInt64, TypeUint64, TypeBoolean:
		for _, n := range ra.Ints {
			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, uint64(n))
			blobs = append(blobs, b)
		}
	case TypeString:
		for _, s := range ra.Strings {
			blobs = append(blobs, encodeUTF16NUL(s))
		}
	case TypeSID:
		for _, s := range ra.SIDs {
			sidBytes, err := encodeSID(s)
			if err != nil {
				return nil, err
			}
			blobs = append(blobs, encodeOctetRelative(sidBytes))
		}
	case TypeOctetString:
		for _, o := range ra.Octets {
			blobs = append(blobs, encodeOctetRelative(o))
		}
	default:
		return nil, fmt.Errorf("unsupported resource attribute value type 0x%04x", ra.ValueType)
	}
	return blobs, nil
}

// Decode parses CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 bytes.
func Decode(data []byte) (*ResourceAttribute, error) {
	if len(data) < headerLen {
		return nil, fmt.Errorf("resource attribute data too short (%d bytes)", len(data))
	}
	nameOffset := binary.LittleEndian.Uint32(data[0:4])
	vt := binary.LittleEndian.Uint16(data[4:6])
	flags := binary.LittleEndian.Uint32(data[8:12])
	count := binary.LittleEndian.Uint32(data[12:16])

	if _, ok := valueTypeToSDDLType[vt]; !ok {
		return nil, fmt.Errorf("unknown resource attribute value type 0x%04x", vt)
	}
	if int(count) > (len(data)-headerLen)/4 {
		return nil, fmt.Errorf("resource attribute value count %d exceeds available data", count)
	}

	ra := &ResourceAttribute{ValueType: vt, Flags: flags}

	name, err := decodeUTF16NUL(data, int(nameOffset))
	if err != nil {
		return nil, fmt.Errorf("invalid resource attribute name: %w", err)
	}
	ra.Name = name

	for i := 0; i < int(count); i++ {
		off := binary.LittleEndian.Uint32(data[headerLen+4*i : headerLen+4*i+4])
		if err := ra.decodeValue(data, int(off)); err != nil {
			return nil, err
		}
	}
	return ra, nil
}

func (ra *ResourceAttribute) decodeValue(data []byte, off int) error {
	switch ra.ValueType {
	case TypeInt64, TypeUint64, TypeBoolean:
		if off < 0 || off+8 > len(data) {
			return fmt.Errorf("integer value offset %d out of range", off)
		}
		ra.Ints = append(ra.Ints, int64(binary.LittleEndian.Uint64(data[off:off+8])))
	case TypeString:
		s, err := decodeUTF16NUL(data, off)
		if err != nil {
			return err
		}
		ra.Strings = append(ra.Strings, s)
	case TypeSID:
		b, err := decodeOctetRelative(data, off)
		if err != nil {
			return err
		}
		sd := &sid.SID{}
		if _, err := sd.Unmarshal(b); err != nil {
			return fmt.Errorf("invalid SID resource attribute value: %w", err)
		}
		ra.SIDs = append(ra.SIDs, sd.ToString())
	case TypeOctetString:
		b, err := decodeOctetRelative(data, off)
		if err != nil {
			return err
		}
		ra.Octets = append(ra.Octets, b)
	}
	return nil
}

// String renders the resource attribute as SDDL attribute-data text (without an
// outer pair of parentheses).
func (ra *ResourceAttribute) String() string {
	var sb strings.Builder
	sb.WriteString("\"")
	sb.WriteString(ra.Name)
	sb.WriteString("\",")
	sb.WriteString(valueTypeToSDDLType[ra.ValueType])
	sb.WriteString(",")
	sb.WriteString(strconv.FormatUint(uint64(ra.Flags), 10))

	switch ra.ValueType {
	case TypeInt64:
		for _, n := range ra.Ints {
			sb.WriteString("," + strconv.FormatInt(n, 10))
		}
	case TypeUint64:
		for _, n := range ra.Ints {
			sb.WriteString("," + strconv.FormatUint(uint64(n), 10))
		}
	case TypeBoolean:
		for _, n := range ra.Ints {
			if n == 0 {
				sb.WriteString(",0")
			} else {
				sb.WriteString(",1")
			}
		}
	case TypeString:
		for _, s := range ra.Strings {
			sb.WriteString(",\"" + s + "\"")
		}
	case TypeSID:
		for _, s := range ra.SIDs {
			sb.WriteString("," + s)
		}
	case TypeOctetString:
		for _, o := range ra.Octets {
			sb.WriteString(",#")
			for _, b := range o {
				fmt.Fprintf(&sb, "%02x", b)
			}
		}
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

func encodeUTF16NUL(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(u16)*2+2)
	for _, c := range u16 {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], c)
		out = append(out, b[:]...)
	}
	out = append(out, 0x00, 0x00) // NUL terminator
	return out
}

func decodeUTF16NUL(data []byte, off int) (string, error) {
	if off < 0 || off > len(data) {
		return "", fmt.Errorf("string offset %d out of range", off)
	}
	var u16 []uint16
	for i := off; i+1 < len(data); i += 2 {
		c := binary.LittleEndian.Uint16(data[i : i+2])
		if c == 0 {
			return string(utf16.Decode(u16)), nil
		}
		u16 = append(u16, c)
	}
	return "", fmt.Errorf("unterminated UTF-16 string at offset %d", off)
}

// encodeOctetRelative builds a CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE:
// a DWORD length followed by the bytes.
func encodeOctetRelative(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.LittleEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

func decodeOctetRelative(data []byte, off int) ([]byte, error) {
	if off < 0 || off+4 > len(data) {
		return nil, fmt.Errorf("octet string offset %d out of range", off)
	}
	l := int(binary.LittleEndian.Uint32(data[off : off+4]))
	if off+4+l > len(data) {
		return nil, fmt.Errorf("octet string length %d at offset %d exceeds available data", l, off)
	}
	out := make([]byte, l)
	copy(out, data[off+4:off+4+l])
	return out, nil
}

func encodeSID(s string) ([]byte, error) {
	resolved := strings.TrimSpace(s)
	if full, ok := sddl_sid.SDDLToSID[resolved]; ok {
		resolved = full
	}
	if !strings.HasPrefix(resolved, "S-") {
		return nil, fmt.Errorf("unknown SID %q in resource attribute", s)
	}
	sd := &sid.SID{}
	if err := sd.FromString(resolved); err != nil {
		return nil, fmt.Errorf("invalid SID %q: %w", s, err)
	}
	return sd.Marshal()
}

// ---------------------------------------------------------------------------
// SDDL text helpers
// ---------------------------------------------------------------------------

// splitTopLevelCommas splits on commas that are not inside a double-quoted
// string.
func splitTopLevelCommas(s string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case c == ',' && !inQuote:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	parts = append(parts, cur.String())
	return parts
}

func parseQuoted(s string) (string, error) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", fmt.Errorf("expected a double-quoted string, got %q", s)
	}
	return s[1 : len(s)-1], nil
}

func parseIntAuto(s string) (int64, error) {
	neg := false
	body := s
	if strings.HasPrefix(body, "-") {
		neg = true
		body = body[1:]
	} else if strings.HasPrefix(body, "+") {
		body = body[1:]
	}
	var v int64
	var err error
	switch {
	case strings.HasPrefix(body, "0x") || strings.HasPrefix(body, "0X"):
		v, err = strconv.ParseInt(body[2:], 16, 64)
	default:
		v, err = strconv.ParseInt(body, 10, 64)
	}
	if err != nil {
		return 0, err
	}
	if neg {
		v = -v
	}
	return v, nil
}

func parseUintAuto(s string) (uint64, error) {
	body := s
	if strings.HasPrefix(body, "0x") || strings.HasPrefix(body, "0X") {
		return strconv.ParseUint(body[2:], 16, 64)
	}
	return strconv.ParseUint(body, 10, 64)
}

func parseOctet(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "#") {
		return nil, fmt.Errorf("octet string must start with '#'")
	}
	// Per MS-DTYP, '#' is synonymous with '0' padding inside octet strings.
	hexs := strings.ReplaceAll(s[1:], "#", "0")
	if len(hexs)%2 != 0 {
		return nil, fmt.Errorf("octet string has an odd number of hex digits")
	}
	out := make([]byte, 0, len(hexs)/2)
	for i := 0; i < len(hexs); i += 2 {
		b, err := strconv.ParseUint(hexs[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out = append(out, byte(b))
	}
	return out, nil
}
