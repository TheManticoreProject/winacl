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
		// Member_of family: `Member_of {SID(...), ...}`.
		return operatorNames[v.Op] + " " + serializeNode(v.Operand, 0)
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
	var body string
	switch v.Base {
	case baseHex:
		if v.Value >= 0 {
			body = "0x" + strconv.FormatInt(v.Value, 16)
		} else {
			body = strconv.FormatInt(v.Value, 10)
		}
	case baseOctal:
		if v.Value >= 0 {
			body = "0" + strconv.FormatInt(v.Value, 8)
		} else {
			body = strconv.FormatInt(v.Value, 10)
		}
	default:
		body = strconv.FormatInt(v.Value, 10)
	}
	// A negative value already carries its '-'; only add an explicit '+'.
	if v.Sign == signPositive && v.Value >= 0 {
		body = "+" + body
	}
	return body
}
