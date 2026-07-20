package condition

import (
	"fmt"
	"strconv"
	"strings"
)

// Precedence levels for parenthesization when serializing logical operators.
const (
	precOr   = 1 // ||
	precAnd  = 2 // &&
	precAtom = 3 // relational terms, unary ops, literals, attributes
)

func nodePrecedence(n Node) int {
	if b, ok := n.(*BinaryOp); ok {
		switch b.Op {
		case tokenOr:
			return precOr
		case tokenAnd:
			return precAnd
		}
	}
	return precAtom
}

// serializeNode renders a node as SDDL text. parentPrec is the precedence of
// the enclosing logical operator (0 at the top level); a child logical
// expression of strictly lower precedence is wrapped in parentheses.
func serializeNode(n Node, parentPrec int) string {
	switch v := n.(type) {
	case *Attribute:
		return attributeText(v)

	case *IntLiteral:
		return intText(v)

	case *StringLiteral:
		return "\"" + v.Value + "\""

	case *OctetLiteral:
		var sb strings.Builder
		sb.WriteByte('#')
		for _, b := range v.Value {
			fmt.Fprintf(&sb, "%02x", b)
		}
		return sb.String()

	case *SIDLiteral:
		return "SID(" + v.SID + ")"

	case *Composite:
		parts := make([]string, len(v.Items))
		for i, it := range v.Items {
			parts[i] = serializeNode(it, 0)
		}
		return "{" + strings.Join(parts, ", ") + "}"

	case *UnaryOp:
		return serializeUnary(v)

	case *BinaryOp:
		return serializeBinary(v, parentPrec)
	}
	return ""
}

func serializeUnary(v *UnaryOp) string {
	switch v.Op {
	case tokenNot:
		// Wrap the operand so precedence is unambiguous on re-parse.
		return "!(" + serializeNode(v.Operand, 0) + ")"
	case tokenExists, tokenNotExists:
		return operatorNames[v.Op] + " " + serializeNode(v.Operand, 0)
	default:
		// Member_of family: the SDDL text form requires the operand to be a
		// brace-delimited SID array (`Member_of {SID(...), ...}`). The binary
		// form also permits a bare SID literal operand (MS-DTYP 2.4.4.17.6), so
		// wrap a non-composite operand in braces to produce re-parseable text.
		operand := serializeNode(v.Operand, 0)
		if _, isComposite := v.Operand.(*Composite); !isComposite {
			operand = "{" + operand + "}"
		}
		return operatorNames[v.Op] + " " + operand
	}
}

func serializeBinary(v *BinaryOp, parentPrec int) string {
	if v.Op == tokenAnd || v.Op == tokenOr {
		p := nodePrecedence(v)
		left := serializeNode(v.Left, p)
		right := serializeNode(v.Right, p)
		if nodePrecedence(v.Left) < p {
			left = "(" + left + ")"
		}
		if nodePrecedence(v.Right) < p {
			right = "(" + right + ")"
		}
		return left + " " + operatorNames[v.Op] + " " + right
	}
	// Relational operator: `LHS op RHS`.
	return serializeNode(v.Left, 0) + " " + operatorNames[v.Op] + " " + serializeNode(v.Right, 0)
}

func attributeText(a *Attribute) string {
	switch a.Token {
	case tokenUserAttr:
		return "@User." + a.Name
	case tokenDeviceAttr:
		return "@Device." + a.Name
	case tokenResourceAttr:
		return "@Resource." + a.Name
	default:
		return a.Name
	}
}

func intText(v *IntLiteral) string {
	// Format the magnitude in the recorded base, then re-apply the sign, so a
	// negative hex/octal literal keeps its base (e.g. -0x5 stays hex) and its
	// Base byte round-trips. uint64(-v.Value) yields the correct magnitude even
	// for math.MinInt64 (two's-complement wraparound).
	neg := v.Value < 0
	var mag uint64
	if neg {
		mag = uint64(-v.Value)
	} else {
		mag = uint64(v.Value)
	}

	var body string
	switch v.Base {
	case baseHex:
		body = "0x" + strconv.FormatUint(mag, 16)
	case baseOctal:
		body = "0" + strconv.FormatUint(mag, 8)
	default:
		body = strconv.FormatUint(mag, 10)
	}

	if neg {
		body = "-" + body
	} else if v.Sign == signPositive {
		body = "+" + body
	}
	return body
}
