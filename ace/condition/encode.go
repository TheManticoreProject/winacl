package condition

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	sddl_sid "github.com/TheManticoreProject/winacl/sddl/sid"
	"github.com/TheManticoreProject/winacl/sid"
)

// encodeNode emits a node in postfix order.
func encodeNode(n Node) ([]byte, error) {
	switch v := n.(type) {
	case *Attribute:
		out := []byte{v.Token}
		out = append(out, encodeUTF16LenPrefixed(v.Name)...)
		return out, nil

	case *IntLiteral:
		out := make([]byte, 0, 11)
		out = append(out, v.Width)
		var q [8]byte
		binary.LittleEndian.PutUint64(q[:], uint64(v.Value))
		out = append(out, q[:]...)
		out = append(out, v.Sign, v.Base)
		return out, nil

	case *StringLiteral:
		out := []byte{tokenUnicode}
		out = append(out, encodeUTF16LenPrefixed(v.Value)...)
		return out, nil

	case *OctetLiteral:
		out := []byte{tokenOctet}
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(v.Value)))
		out = append(out, l[:]...)
		out = append(out, v.Value...)
		return out, nil

	case *SIDLiteral:
		sidBytes, err := encodeSID(v.SID)
		if err != nil {
			return nil, err
		}
		out := []byte{tokenSID}
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(sidBytes)))
		out = append(out, l[:]...)
		out = append(out, sidBytes...)
		return out, nil

	case *Composite:
		var body []byte
		for _, item := range v.Items {
			b, err := encodeNode(item)
			if err != nil {
				return nil, err
			}
			body = append(body, b...)
		}
		out := []byte{tokenComposite}
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(body)))
		out = append(out, l[:]...)
		out = append(out, body...)
		return out, nil

	case *UnaryOp:
		operand, err := encodeNode(v.Operand)
		if err != nil {
			return nil, err
		}
		return append(operand, v.Op), nil

	case *BinaryOp:
		left, err := encodeNode(v.Left)
		if err != nil {
			return nil, err
		}
		right, err := encodeNode(v.Right)
		if err != nil {
			return nil, err
		}
		out := append(left, right...)
		return append(out, v.Op), nil
	}
	return nil, fmt.Errorf("cannot encode conditional-expression node of type %T", n)
}

// encodeUTF16LenPrefixed encodes s as a DWORD byte-length followed by the
// UTF-16LE code units (no NUL terminator), as used by both Unicode string
// literals and attribute-name tokens.
func encodeUTF16LenPrefixed(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, 4, 4+len(u16)*2)
	binary.LittleEndian.PutUint32(out, uint32(len(u16)*2))
	for _, c := range u16 {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], c)
		out = append(out, b[:]...)
	}
	return out
}

// encodeSID resolves an SDDL SID alias or S-string and returns its binary form.
func encodeSID(s string) ([]byte, error) {
	resolved := s
	if full, ok := sddl_sid.SDDLToSID[strings.TrimSpace(s)]; ok {
		resolved = full
	}
	if !strings.HasPrefix(resolved, "S-") {
		return nil, fmt.Errorf("unknown SID %q in conditional expression", s)
	}
	sd := &sid.SID{}
	if err := sd.FromString(resolved); err != nil {
		return nil, fmt.Errorf("invalid SID %q: %w", s, err)
	}
	return sd.Marshal()
}
