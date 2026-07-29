package condition

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/TheManticoreProject/winacl/sid"
)

// decodeTokens runs the postfix token stream (without the artx signature)
// through a stack machine and returns the reconstructed AST.
func decodeTokens(data []byte) (Node, error) {
	var stack []Node
	pop := func() (Node, error) {
		if len(stack) == 0 {
			return nil, fmt.Errorf("conditional expression underflow: operator with no operand")
		}
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return n, nil
	}

	i := 0
	for i < len(data) {
		tok := data[i]
		if tok == tokenPadding {
			// Trailing DWORD padding; nothing else follows.
			break
		}
		node, n, err := decodeToken(data[i:])
		if err != nil {
			return nil, err
		}
		if node != nil {
			// Literal / attribute / composite operand.
			stack = append(stack, node)
			i += n
			continue
		}

		// Operator token (single byte).
		switch {
		case isUnaryOperator(tok):
			operand, err := pop()
			if err != nil {
				return nil, err
			}
			stack = append(stack, &UnaryOp{Op: tok, Operand: operand})
		case isBinaryOperator(tok):
			right, err := pop()
			if err != nil {
				return nil, err
			}
			left, err := pop()
			if err != nil {
				return nil, err
			}
			stack = append(stack, &BinaryOp{Op: tok, Left: left, Right: right})
		default:
			return nil, fmt.Errorf("unknown conditional-expression token 0x%02x", tok)
		}
		i++
	}

	if len(stack) != 1 {
		return nil, fmt.Errorf("malformed conditional expression: %d values left on the stack", len(stack))
	}
	return stack[0], nil
}

// decodeToken decodes a single operand token at the start of data. It returns
// (nil, 0, nil) when the leading byte is an operator (handled by the caller).
func decodeToken(data []byte) (Node, int, error) {
	tok := data[0]
	switch tok {
	case tokenInt8, tokenInt16, tokenInt32, tokenInt64:
		if len(data) < 11 {
			return nil, 0, fmt.Errorf("truncated integer literal")
		}
		value := int64(binary.LittleEndian.Uint64(data[1:9]))
		sign := data[9]
		base := data[10]
		return &IntLiteral{Value: value, Width: tok, Sign: sign, Base: base}, 11, nil

	case tokenUnicode:
		s, n, err := decodeUTF16LenPrefixed(data[1:])
		if err != nil {
			return nil, 0, err
		}
		return &StringLiteral{Value: s}, 1 + n, nil

	case tokenOctet:
		if len(data) < 5 {
			return nil, 0, fmt.Errorf("truncated octet string")
		}
		l := int(binary.LittleEndian.Uint32(data[1:5]))
		if 5+l > len(data) {
			return nil, 0, fmt.Errorf("octet string length %d exceeds available data", l)
		}
		b := make([]byte, l)
		copy(b, data[5:5+l])
		return &OctetLiteral{Value: b}, 5 + l, nil

	case tokenSID:
		if len(data) < 5 {
			return nil, 0, fmt.Errorf("truncated SID literal")
		}
		l := int(binary.LittleEndian.Uint32(data[1:5]))
		if 5+l > len(data) {
			return nil, 0, fmt.Errorf("SID literal length %d exceeds available data", l)
		}
		sd := &sid.SID{}
		if _, err := sd.Unmarshal(data[5 : 5+l]); err != nil {
			return nil, 0, fmt.Errorf("invalid SID literal: %w", err)
		}
		return &SIDLiteral{SID: sd.ToString()}, 5 + l, nil

	case tokenComposite:
		if len(data) < 5 {
			return nil, 0, fmt.Errorf("truncated composite literal")
		}
		l := int(binary.LittleEndian.Uint32(data[1:5]))
		if 5+l > len(data) {
			return nil, 0, fmt.Errorf("composite length %d exceeds available data", l)
		}
		items, err := decodeComposite(data[5 : 5+l])
		if err != nil {
			return nil, 0, err
		}
		return &Composite{Items: items}, 5 + l, nil

	case tokenLocalAttr, tokenUserAttr, tokenResourceAttr, tokenDeviceAttr, tokenTokenAttr:
		s, n, err := decodeUTF16LenPrefixed(data[1:])
		if err != nil {
			return nil, 0, err
		}
		return &Attribute{Token: tok, Name: s}, 1 + n, nil
	}

	// Not an operand token; leave it for the caller's operator handling.
	return nil, 0, nil
}

// decodeComposite decodes the concatenated literal tokens inside a composite.
func decodeComposite(data []byte) ([]Node, error) {
	var items []Node
	i := 0
	for i < len(data) {
		node, n, err := decodeToken(data[i:])
		if err != nil {
			return nil, err
		}
		if node == nil {
			return nil, fmt.Errorf("unexpected operator token 0x%02x inside composite", data[i])
		}
		items = append(items, node)
		i += n
	}
	return items, nil
}

// decodeUTF16LenPrefixed reads a DWORD byte-length followed by UTF-16LE units.
func decodeUTF16LenPrefixed(data []byte) (string, int, error) {
	if len(data) < 4 {
		return "", 0, fmt.Errorf("truncated length-prefixed string")
	}
	l := int(binary.LittleEndian.Uint32(data[0:4]))
	if l%2 != 0 {
		return "", 0, fmt.Errorf("length-prefixed string has odd byte length %d", l)
	}
	if 4+l > len(data) {
		return "", 0, fmt.Errorf("string length %d exceeds available data", l)
	}
	u16 := make([]uint16, l/2)
	for j := 0; j < l/2; j++ {
		u16[j] = binary.LittleEndian.Uint16(data[4+j*2 : 4+j*2+2])
	}
	return string(utf16.Decode(u16)), 4 + l, nil
}

func isUnaryOperator(tok byte) bool {
	switch tok {
	case tokenNot, tokenExists, tokenNotExists:
		return true
	}
	return isMemberOfOperator(tok)
}

func isBinaryOperator(tok byte) bool {
	switch tok {
	case tokenEqual, tokenNotEqual, tokenLessThan, tokenLessOrEqual, tokenGreaterThan,
		tokenGreaterOrEqual, tokenContains, tokenAnyOf, tokenNotContains, tokenNotAnyOf,
		tokenAnd, tokenOr:
		return true
	}
	return false
}
