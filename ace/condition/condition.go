// Package condition implements the conditional-expression codec used by
// conditional (callback) ACEs, as specified in MS-DTYP 2.4.4.17 and its
// subsections (2.4.4.17.1 Conditional ACE Expressions, and the Literal /
// Attribute / Relational / Logical operator token tables).
//
// A conditional expression lives in the ApplicationData member of a callback
// ACE, prefixed by the 4-byte ACE_CONDITION_SIGNATURE "artx" (0x61 0x72 0x74
// 0x78). The remainder is a series of tokens in postfix (reverse Polish) order.
// This package converts between the SDDL textual form of a conditional
// expression (e.g. `(@User.Title=="PM" && @User.Division=="Finance")`) and that
// binary form.
//
//	text -> Marshal   -> ApplicationData bytes ("artx" + tokens + DWORD padding)
//	bytes -> Unmarshal -> text
//
// All multibyte integers (including UTF-16 characters) are stored
// least-significant byte first, and the encoded expression is padded with 0x00
// to a DWORD (4-byte) boundary.
package condition

import (
	"fmt"
	"strings"
)

// ACE_CONDITION_SIGNATURE marks a callback ACE's ApplicationData as a
// conditional expression (MS-DTYP 2.4.4.17.1).
var ACE_CONDITION_SIGNATURE = []byte{0x61, 0x72, 0x74, 0x78}

// Literal, attribute, and operator token byte-codes (MS-DTYP 2.4.4.17.1.x).
const (
	tokenPadding byte = 0x00

	// Literal tokens.
	tokenInt8      byte = 0x01
	tokenInt16     byte = 0x02
	tokenInt32     byte = 0x03
	tokenInt64     byte = 0x04
	tokenUnicode   byte = 0x10
	tokenOctet     byte = 0x18
	tokenComposite byte = 0x50
	tokenSID       byte = 0x51

	// Attribute-name tokens (encoding identical to a Unicode string).
	tokenLocalAttr    byte = 0xf8
	tokenUserAttr     byte = 0xf9
	tokenResourceAttr byte = 0xfa
	tokenDeviceAttr   byte = 0xfb
	// tokenTokenAttr is a fifth attribute type that Windows implements but
	// MS-DTYP 2.4.4.17.8 does not document, carrying the SDDL prefix "@TOKEN.".
	// Its encoding is identical to the other attribute tokens. The kernel
	// evaluator treats it as its own attribute source, read from the access
	// token rather than from the user-claims collection that 0xf9 uses, so it is
	// not a synonym for tokenUserAttr.
	tokenTokenAttr byte = 0xfc

	// Binary relational operators.
	tokenEqual          byte = 0x80
	tokenNotEqual       byte = 0x81
	tokenLessThan       byte = 0x82
	tokenLessOrEqual    byte = 0x83
	tokenGreaterThan    byte = 0x84
	tokenGreaterOrEqual byte = 0x85
	tokenContains       byte = 0x86
	tokenAnyOf          byte = 0x88
	tokenNotContains    byte = 0x8e
	tokenNotAnyOf       byte = 0x8f

	// Unary relational operators (operand is a SID literal or a composite of SIDs).
	tokenMemberOf             byte = 0x89
	tokenDeviceMemberOf       byte = 0x8a
	tokenMemberOfAny          byte = 0x8b
	tokenDeviceMemberOfAny    byte = 0x8c
	tokenNotMemberOf          byte = 0x90
	tokenNotDeviceMemberOf    byte = 0x91
	tokenNotMemberOfAny       byte = 0x92
	tokenNotDeviceMemberOfAny byte = 0x93

	// Unary logical operators.
	tokenExists    byte = 0x87
	tokenNotExists byte = 0x8d
	tokenNot       byte = 0xa2

	// Binary logical operators.
	tokenAnd byte = 0xa0
	tokenOr  byte = 0xa1

	// tokenBitwiseAnd is an operator that Windows implements but MS-DTYP does not
	// document: neither the relational table (2.4.4.17.6, which stops at 0x93) nor
	// the logical table (2.4.4.17.7, which defines only 0xa0/0xa1/0xa2) lists it,
	// and the 2.5.1.1 ABNF has "&&" but never a lone "&".
	//
	// It is a bitwise AND of two 64-bit integer operands, evaluating TRUE when the
	// result is non-zero, so it reads as a flag test: (@Resource.flags & 4).
	//
	// It is parsed here as a binary relational operator, because that is what its
	// operands are: a value-bearing left side and a literal or attribute on the
	// right, the same shape as ==. Note one deliberate divergence from Windows in
	// the text grammar: Windows' operator table gives '&' precedence 10, the lowest
	// of all the binary operators (|| is 11, && is 12), so Windows groups
	// "a & b || c" as "a & (b || c)". This package groups it as "(a & b) || c",
	// like every other relational operator. The Windows grouping is ill-typed by
	// '&'s own operand rules - the right side would be a logical result rather than
	// an integer - so it cannot evaluate to TRUE, and no meaningful descriptor
	// depends on it. Parenthesize explicitly if the exact Windows tree is required;
	// the binary form round-trips either tree faithfully.
	tokenBitwiseAnd byte = 0xa3
)

// Base codes for integer literals (MS-DTYP 2.4.4.17.5).
const (
	baseOctal   byte = 0x01
	baseDecimal byte = 0x02
	baseHex     byte = 0x03
)

// Sign codes for integer literals (MS-DTYP 2.4.4.17.5).
const (
	signPositive byte = 0x01
	signNegative byte = 0x02
	signNone     byte = 0x03
)

// wordOperators maps the SDDL keyword operators to their token byte-codes, in the
// capitalisation used by the MS-DTYP 2.4.4.17.6 and 2.4.4.17.7 tables.
//
// Look operators up with lookupWordOperator rather than indexing this map
// directly: SDDL keyword operators are not case-sensitive, and more than one
// capitalisation is in circulation. MS-DTYP spells the four "any" operators
// Member_of_Any, while the operator-name tables in Windows' own sechost.dll and
// advapi32.dll spell them Member_of_any.
var wordOperators = map[string]byte{
	"Contains":                 tokenContains,
	"Not_Contains":             tokenNotContains,
	"Any_of":                   tokenAnyOf,
	"Not_Any_of":               tokenNotAnyOf,
	"Member_of":                tokenMemberOf,
	"Device_Member_of":         tokenDeviceMemberOf,
	"Member_of_Any":            tokenMemberOfAny,
	"Device_Member_of_Any":     tokenDeviceMemberOfAny,
	"Not_Member_of":            tokenNotMemberOf,
	"Not_Device_Member_of":     tokenNotDeviceMemberOf,
	"Not_Member_of_Any":        tokenNotMemberOfAny,
	"Not_Device_Member_of_Any": tokenNotDeviceMemberOfAny,
	"Exists":                   tokenExists,
	"Not_Exists":               tokenNotExists,
}

// wordOperatorsFolded is wordOperators re-keyed on the lowercased operator name,
// so lookups can be case-insensitive without a linear scan.
var wordOperatorsFolded = func() map[string]byte {
	folded := make(map[string]byte, len(wordOperators))
	for name, token := range wordOperators {
		folded[strings.ToLower(name)] = token
	}
	return folded
}()

// lookupWordOperator resolves an SDDL keyword operator to its token byte-code,
// ignoring case.
func lookupWordOperator(name string) (byte, bool) {
	token, ok := wordOperatorsFolded[strings.ToLower(name)]
	return token, ok
}

// operatorNames is the reverse of wordOperators plus the symbolic operators,
// used when serializing an AST back to SDDL text. Serialization always emits the
// MS-DTYP capitalisation.
var operatorNames = map[byte]string{
	tokenAnd:                  "&&",
	tokenOr:                   "||",
	tokenBitwiseAnd:           "&",
	tokenNot:                  "!",
	tokenEqual:                "==",
	tokenNotEqual:             "!=",
	tokenLessThan:             "<",
	tokenLessOrEqual:          "<=",
	tokenGreaterThan:          ">",
	tokenGreaterOrEqual:       ">=",
	tokenContains:             "Contains",
	tokenNotContains:          "Not_Contains",
	tokenAnyOf:                "Any_of",
	tokenNotAnyOf:             "Not_Any_of",
	tokenMemberOf:             "Member_of",
	tokenDeviceMemberOf:       "Device_Member_of",
	tokenMemberOfAny:          "Member_of_Any",
	tokenDeviceMemberOfAny:    "Device_Member_of_Any",
	tokenNotMemberOf:          "Not_Member_of",
	tokenNotDeviceMemberOf:    "Not_Device_Member_of",
	tokenNotMemberOfAny:       "Not_Member_of_Any",
	tokenNotDeviceMemberOfAny: "Not_Device_Member_of_Any",
	tokenExists:               "Exists",
	tokenNotExists:            "Not_Exists",
}

// isRelationalWordOperator reports whether tok is one of the keyword operators
// that take a left- and a right-hand side, and so may appear in infix position.
func isRelationalWordOperator(tok byte) bool {
	switch tok {
	case tokenContains, tokenNotContains, tokenAnyOf, tokenNotAnyOf:
		return true
	}
	return false
}

func isMemberOfOperator(tok byte) bool {
	switch tok {
	case tokenMemberOf, tokenDeviceMemberOf, tokenMemberOfAny, tokenDeviceMemberOfAny,
		tokenNotMemberOf, tokenNotDeviceMemberOf, tokenNotMemberOfAny, tokenNotDeviceMemberOfAny:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Abstract syntax tree
// ---------------------------------------------------------------------------

// Node is a node in a conditional-expression AST.
type Node interface {
	isNode()
}

// Attribute is an attribute-name operand (local or @User./@Resource./@Device.).
type Attribute struct {
	Token byte // one of tokenLocalAttr/tokenUserAttr/tokenResourceAttr/tokenDeviceAttr/tokenTokenAttr
	Name  string
}

// IntLiteral is an integer literal. Width is the token byte-code (int8..int64),
// Base and Sign preserve the textual representation for lossless round-tripping.
type IntLiteral struct {
	Value int64
	Width byte
	Base  byte
	Sign  byte
}

// StringLiteral is a Unicode string literal.
type StringLiteral struct{ Value string }

// OctetLiteral is an octet (byte) string literal (SDDL "#hex" form).
type OctetLiteral struct{ Value []byte }

// SIDLiteral is a SID literal (SDDL "SID(...)" form).
type SIDLiteral struct{ SID string }

// Composite is a braced set of literals ("{a,b,c}").
type Composite struct{ Items []Node }

// UnaryOp applies a unary operator (logical !, Exists/Not_Exists, or a
// Member_of-family operator) to a single operand.
type UnaryOp struct {
	Op      byte
	Operand Node
}

// BinaryOp applies a binary operator (relational or logical) to two operands.
type BinaryOp struct {
	Op          byte
	Left, Right Node
}

func (*Attribute) isNode()     {}
func (*IntLiteral) isNode()    {}
func (*StringLiteral) isNode() {}
func (*OctetLiteral) isNode()  {}
func (*SIDLiteral) isNode()    {}
func (*Composite) isNode()     {}
func (*UnaryOp) isNode()       {}
func (*BinaryOp) isNode()      {}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// IsConditional reports whether applicationData carries a conditional
// expression, i.e. whether it begins with the ACE_CONDITION_SIGNATURE.
func IsConditional(applicationData []byte) bool {
	return len(applicationData) >= 4 &&
		applicationData[0] == ACE_CONDITION_SIGNATURE[0] &&
		applicationData[1] == ACE_CONDITION_SIGNATURE[1] &&
		applicationData[2] == ACE_CONDITION_SIGNATURE[2] &&
		applicationData[3] == ACE_CONDITION_SIGNATURE[3]
}

// Marshal parses an SDDL conditional-expression string and returns the binary
// ApplicationData encoding (signature + postfix token stream + DWORD padding).
// The input may optionally be wrapped in a single outer pair of parentheses, as
// it appears in an ACE string.
func Marshal(expr string) ([]byte, error) {
	root, err := Parse(expr)
	if err != nil {
		return nil, err
	}
	return Encode(root)
}

// Unmarshal decodes binary conditional-expression ApplicationData into its SDDL
// textual form (without an outer pair of parentheses).
func Unmarshal(applicationData []byte) (string, error) {
	root, err := Decode(applicationData)
	if err != nil {
		return "", err
	}
	return Serialize(root), nil
}

// Parse converts an SDDL conditional-expression string into an AST.
func Parse(expr string) (Node, error) {
	toks, err := lex(expr)
	if err != nil {
		return nil, err
	}
	p := &parser{tokens: toks}
	node, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if !p.atEnd() {
		return nil, fmt.Errorf("unexpected trailing input at token %q", p.peek().text)
	}
	return node, nil
}

// Encode serializes an AST into binary ApplicationData.
func Encode(root Node) ([]byte, error) {
	out := make([]byte, 0, 32)
	out = append(out, ACE_CONDITION_SIGNATURE...)
	body, err := encodeNode(root)
	if err != nil {
		return nil, err
	}
	out = append(out, body...)
	// Pad to a DWORD boundary with 0x00.
	for len(out)%4 != 0 {
		out = append(out, 0x00)
	}
	return out, nil
}

// Decode parses binary ApplicationData into an AST.
func Decode(data []byte) (Node, error) {
	if !IsConditional(data) {
		return nil, fmt.Errorf("application data is not a conditional expression (missing artx signature)")
	}
	return decodeTokens(data[4:])
}

// Serialize converts an AST back into an SDDL conditional-expression string
// (without an outer pair of parentheses).
func Serialize(root Node) string {
	return serializeNode(root, 0)
}
