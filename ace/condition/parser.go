package condition

import (
	"fmt"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

type tokKind int

const (
	tkWord tokKind = iota // attribute name or keyword operator
	tkString
	tkInt
	tkOctet
	tkSymbol // ( ) { } , == != < <= > >= && || !
)

type lexToken struct {
	kind tokKind
	text string
}

func isWordByte(b byte) bool {
	// attr-char1 plus '@' and '.' so a full @Prefixed name lexes as one word,
	// and '-' so a SID string (e.g. S-1-5-32-544) inside SID(...) is a single
	// word. A leading '-' is still lexed as an integer sign because the integer
	// case is matched before the word case.
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') || b == ':' || b == '.' || b == '/' || b == '_' || b == '@' || b == '-'
}

func lex(s string) ([]lexToken, error) {
	var toks []lexToken
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '(' || c == ')' || c == '{' || c == '}' || c == ',':
			toks = append(toks, lexToken{tkSymbol, string(c)})
			i++
		case c == '"':
			// String literal: read to the closing quote (no escaping is defined).
			j := i + 1
			for j < len(s) && s[j] != '"' {
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("unterminated string literal")
			}
			toks = append(toks, lexToken{tkString, s[i+1 : j]})
			i = j + 1
		case c == '#':
			// Octet string: '#' followed by hex digit pairs.
			j := i + 1
			for j < len(s) && isHexDigit(s[j]) {
				j++
			}
			toks = append(toks, lexToken{tkOctet, s[i:j]})
			i = j
		case c == '=' || c == '!' || c == '<' || c == '>' || c == '&' || c == '|':
			sym, n, err := lexSymbolOperator(s[i:])
			if err != nil {
				return nil, err
			}
			toks = append(toks, lexToken{tkSymbol, sym})
			i += n
		case c == '+' || c == '-' || (c >= '0' && c <= '9'):
			// Integer literal (optionally signed).
			j := i
			if s[j] == '+' || s[j] == '-' {
				j++
			}
			for j < len(s) && (isAlnum(s[j])) {
				j++
			}
			toks = append(toks, lexToken{tkInt, s[i:j]})
			i = j
		case isWordByte(c):
			j := i
			for j < len(s) && isWordByte(s[j]) {
				j++
			}
			toks = append(toks, lexToken{tkWord, s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q in conditional expression", c)
		}
	}
	return toks, nil
}

func lexSymbolOperator(s string) (string, int, error) {
	switch {
	case strings.HasPrefix(s, "=="):
		return "==", 2, nil
	case strings.HasPrefix(s, "!="):
		return "!=", 2, nil
	case strings.HasPrefix(s, "<="):
		return "<=", 2, nil
	case strings.HasPrefix(s, ">="):
		return ">=", 2, nil
	case strings.HasPrefix(s, "&&"):
		return "&&", 2, nil
	case strings.HasPrefix(s, "||"):
		return "||", 2, nil
	case s[0] == '<':
		return "<", 1, nil
	case s[0] == '>':
		return ">", 1, nil
	case s[0] == '!':
		return "!", 1, nil
	}
	return "", 0, fmt.Errorf("invalid operator near %q", s)
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// ---------------------------------------------------------------------------
// Recursive-descent parser (precedence: || < && < unary/relational/atom)
// ---------------------------------------------------------------------------

type parser struct {
	tokens []lexToken
	pos    int
}

func (p *parser) atEnd() bool { return p.pos >= len(p.tokens) }
func (p *parser) peek() lexToken {
	if p.atEnd() {
		return lexToken{}
	}
	return p.tokens[p.pos]
}
func (p *parser) next() lexToken { t := p.peek(); p.pos++; return t }
func (p *parser) isSymbol(s string) bool {
	t := p.peek()
	return !p.atEnd() && t.kind == tkSymbol && t.text == s
}

// expr = super-term *( "||" super-term )
func (p *parser) parseExpr() (Node, error) {
	left, err := p.parseSuperTerm()
	if err != nil {
		return nil, err
	}
	for p.isSymbol("||") {
		p.next()
		right, err := p.parseSuperTerm()
		if err != nil {
			return nil, err
		}
		left = &BinaryOp{Op: tokenOr, Left: left, Right: right}
	}
	return left, nil
}

// super-term = factor *( "&&" factor )
func (p *parser) parseSuperTerm() (Node, error) {
	left, err := p.parseFactor()
	if err != nil {
		return nil, err
	}
	for p.isSymbol("&&") {
		p.next()
		right, err := p.parseFactor()
		if err != nil {
			return nil, err
		}
		left = &BinaryOp{Op: tokenAnd, Left: left, Right: right}
	}
	return left, nil
}

// factor = "(" expr ")" | "!" factor | term
func (p *parser) parseFactor() (Node, error) {
	if p.isSymbol("(") {
		p.next()
		node, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if !p.isSymbol(")") {
			return nil, fmt.Errorf("expected ')' to close parenthesized expression")
		}
		p.next()
		return node, nil
	}
	if p.isSymbol("!") {
		p.next()
		operand, err := p.parseFactor()
		if err != nil {
			return nil, err
		}
		return &UnaryOp{Op: tokenNot, Operand: operand}, nil
	}
	return p.parseTerm()
}

// term = memberof-op sid-array | exists-op attr | attr [rel-op rhs]
func (p *parser) parseTerm() (Node, error) {
	t := p.peek()
	if p.atEnd() {
		return nil, fmt.Errorf("unexpected end of conditional expression")
	}

	if t.kind == tkWord {
		if op, ok := wordOperators[t.text]; ok {
			// Leading keyword operator: Member_of family or Exists/Not_Exists.
			p.next()
			if isMemberOfOperator(op) {
				operand, err := p.parseSidArray()
				if err != nil {
					return nil, err
				}
				return &UnaryOp{Op: op, Operand: operand}, nil
			}
			if op == tokenExists || op == tokenNotExists {
				attr, err := p.parseAttribute()
				if err != nil {
					return nil, err
				}
				return &UnaryOp{Op: op, Operand: attr}, nil
			}
			return nil, fmt.Errorf("operator %q cannot begin a term", t.text)
		}
	}

	// Otherwise the term begins with an attribute name (LHS).
	lhs, err := p.parseAttribute()
	if err != nil {
		return nil, err
	}

	// An optional relational operator + RHS follows; otherwise the attribute is
	// a standalone term (evaluated for its logical value).
	op, ok := p.peekRelationalOperator()
	if !ok {
		return lhs, nil
	}
	p.consumeRelationalOperator()
	rhs, err := p.parseRHS()
	if err != nil {
		return nil, err
	}
	return &BinaryOp{Op: op, Left: lhs, Right: rhs}, nil
}

// peekRelationalOperator reports the token code of an upcoming relational
// operator (symbolic or keyword) without consuming it.
func (p *parser) peekRelationalOperator() (byte, bool) {
	t := p.peek()
	if p.atEnd() {
		return 0, false
	}
	if t.kind == tkSymbol {
		switch t.text {
		case "==":
			return tokenEqual, true
		case "!=":
			return tokenNotEqual, true
		case "<":
			return tokenLessThan, true
		case "<=":
			return tokenLessOrEqual, true
		case ">":
			return tokenGreaterThan, true
		case ">=":
			return tokenGreaterOrEqual, true
		}
		return 0, false
	}
	if t.kind == tkWord {
		switch t.text {
		case "Contains":
			return tokenContains, true
		case "Not_Contains":
			return tokenNotContains, true
		case "Any_of":
			return tokenAnyOf, true
		case "Not_Any_of":
			return tokenNotAnyOf, true
		}
	}
	return 0, false
}

func (p *parser) consumeRelationalOperator() { p.next() }

// parseRHS parses the right-hand side of a binary relational operator: an
// @Prefixed attribute, a value-array ("{a,b}"), or a single value.
func (p *parser) parseRHS() (Node, error) {
	t := p.peek()
	if p.atEnd() {
		return nil, fmt.Errorf("expected right-hand-side operand")
	}
	if t.kind == tkWord && strings.HasPrefix(t.text, "@") {
		return p.parseAttribute()
	}
	if p.isSymbol("{") {
		return p.parseComposite()
	}
	return p.parseValue()
}

// parseComposite parses "{ value , value , ... }" into a Composite.
func (p *parser) parseComposite() (Node, error) {
	if !p.isSymbol("{") {
		return nil, fmt.Errorf("expected '{' to begin a value set")
	}
	p.next()
	c := &Composite{}
	for {
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		c.Items = append(c.Items, v)
		if p.isSymbol(",") {
			p.next()
			continue
		}
		break
	}
	if !p.isSymbol("}") {
		return nil, fmt.Errorf("expected '}' to close a value set")
	}
	p.next()
	return c, nil
}

// parseSidArray parses a Member_of operand: "{ SID(..) , SID(..) }".
func (p *parser) parseSidArray() (Node, error) {
	if !p.isSymbol("{") {
		return nil, fmt.Errorf("expected '{' to begin a SID array")
	}
	p.next()
	c := &Composite{}
	for {
		s, err := p.parseSidLiteral()
		if err != nil {
			return nil, err
		}
		c.Items = append(c.Items, s)
		if p.isSymbol(",") {
			p.next()
			continue
		}
		break
	}
	if !p.isSymbol("}") {
		return nil, fmt.Errorf("expected '}' to close a SID array")
	}
	p.next()
	return c, nil
}

// parseValue parses a single literal: SID(...), string, octet, or integer.
func (p *parser) parseValue() (Node, error) {
	t := p.peek()
	if p.atEnd() {
		return nil, fmt.Errorf("expected a literal value")
	}
	switch t.kind {
	case tkString:
		p.next()
		return &StringLiteral{Value: t.text}, nil
	case tkOctet:
		p.next()
		return parseOctet(t.text)
	case tkInt:
		p.next()
		return parseInt(t.text)
	case tkWord:
		if t.text == "SID" {
			return p.parseSidLiteral()
		}
	}
	return nil, fmt.Errorf("unexpected token %q where a literal value was expected", t.text)
}

// parseSidLiteral parses "SID( sid-string )".
func (p *parser) parseSidLiteral() (Node, error) {
	t := p.next()
	if t.kind != tkWord || t.text != "SID" {
		return nil, fmt.Errorf("expected 'SID(' literal, got %q", t.text)
	}
	if !p.isSymbol("(") {
		return nil, fmt.Errorf("expected '(' after SID")
	}
	p.next()
	inner := p.peek()
	if inner.kind != tkWord {
		return nil, fmt.Errorf("expected a SID inside SID(...)")
	}
	p.next()
	if !p.isSymbol(")") {
		return nil, fmt.Errorf("expected ')' to close SID(...)")
	}
	p.next()
	return &SIDLiteral{SID: inner.text}, nil
}

// parseAttribute parses an attribute name (local or @Prefixed) into an Attribute.
func (p *parser) parseAttribute() (Node, error) {
	t := p.peek()
	if p.atEnd() || t.kind != tkWord {
		return nil, fmt.Errorf("expected an attribute name")
	}
	p.next()
	name := t.text
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "@user."):
		return &Attribute{Token: tokenUserAttr, Name: name[len("@user."):]}, nil
	case strings.HasPrefix(lower, "@device."):
		return &Attribute{Token: tokenDeviceAttr, Name: name[len("@device."):]}, nil
	case strings.HasPrefix(lower, "@resource."):
		return &Attribute{Token: tokenResourceAttr, Name: name[len("@resource."):]}, nil
	case strings.HasPrefix(name, "@"):
		return nil, fmt.Errorf("unknown attribute prefix in %q", name)
	default:
		return &Attribute{Token: tokenLocalAttr, Name: name}, nil
	}
}

// parseInt parses an SDDL int-64 literal, recording its base and sign so the
// binary encoding round-trips.
func parseInt(s string) (Node, error) {
	sign := signNone
	body := s
	if strings.HasPrefix(body, "+") {
		sign = signPositive
		body = body[1:]
	} else if strings.HasPrefix(body, "-") {
		sign = signNegative
		body = body[1:]
	}

	base := baseDecimal
	var value int64
	var err error
	switch {
	case strings.HasPrefix(body, "0x") || strings.HasPrefix(body, "0X"):
		base = baseHex
		value, err = strconv.ParseInt(body[2:], 16, 64)
	case len(body) > 1 && body[0] == '0':
		base = baseOctal
		value, err = strconv.ParseInt(body[1:], 8, 64)
	default:
		value, err = strconv.ParseInt(body, 10, 64)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid integer literal %q: %w", s, err)
	}
	if sign == signNegative {
		value = -value
	}

	return &IntLiteral{Value: value, Width: intWidth(value), Base: base, Sign: sign}, nil
}

// intWidth selects the smallest signed integer token that holds value.
func intWidth(v int64) byte {
	switch {
	case v >= -128 && v <= 127:
		return tokenInt8
	case v >= -32768 && v <= 32767:
		return tokenInt16
	case v >= -2147483648 && v <= 2147483647:
		return tokenInt32
	default:
		return tokenInt64
	}
}

// parseOctet parses a "#hhhh..." octet-string literal.
func parseOctet(s string) (Node, error) {
	hexs := strings.TrimPrefix(s, "#")
	if len(hexs)%2 != 0 {
		return nil, fmt.Errorf("octet string %q has an odd number of hex digits", s)
	}
	out := make([]byte, 0, len(hexs)/2)
	for i := 0; i < len(hexs); i += 2 {
		b, err := strconv.ParseUint(hexs[i:i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid octet string %q: %w", s, err)
		}
		out = append(out, byte(b))
	}
	return &OctetLiteral{Value: out}, nil
}
