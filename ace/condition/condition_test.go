package condition_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TheManticoreProject/winacl/ace/condition"
)

// TestMarshal_KnownAnswer validates the encoder against the exact byte sequence
// from MS-DTYP 2.4.4.17.2 Example 1 for the conditional expression (Title=="VP").
func TestMarshal_KnownAnswer(t *testing.T) {
	const expr = `(Title=="VP")`
	// artx | f8 local-attr len=10 "Title" | 10 unicode len=4 "VP" | 80 == | 00 00 00 pad
	want := "61727478" +
		"f80a000000" + "540069007400 6c006500" +
		"10" + "04000000" + "560050 00" +
		"80" +
		"000000"
	want = strings.ReplaceAll(want, " ", "")

	got, err := condition.Marshal(expr)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if gotHex := hex.EncodeToString(got); gotHex != want {
		t.Fatalf("Marshal(%q) =\n  %s\nwant\n  %s", expr, gotHex, want)
	}
	if len(got)%4 != 0 {
		t.Fatalf("encoded length %d is not DWORD-aligned", len(got))
	}
}

// TestUnmarshal_KnownAnswer validates the decoder against the same example.
func TestUnmarshal_KnownAnswer(t *testing.T) {
	raw, _ := hex.DecodeString("61727478f80a000000540069007400" + "6c006500" + "1004000000560050008000" + "0000")
	got, err := condition.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got != `Title == "VP"` {
		t.Fatalf("Unmarshal() = %q, want %q", got, `Title == "VP"`)
	}
}

// TestRoundTrip_Binary verifies that Marshal->Unmarshal->Marshal is stable for a
// range of expressions covering every operator/literal/attribute form.
func TestRoundTrip_Binary(t *testing.T) {
	exprs := []string{
		`(Title=="VP")`,
		`(@User.Title=="PM")`,
		`(@User.Title=="PM" && @User.Division=="Finance")`,
		`(@User.Title=="PM" && (@User.Division=="Finance" || @User.Division=="Sales"))`,
		`(@User.smartcard==1 || @Device.managed==1)`,
		`(@Resource.dept Any_of {"Sales", "HR"})`,
		`(@User.clearanceLevel>=@Resource.requiredClearance)`,
		`(Member_of {SID(BA)})`,
		`(Member_of {SID(BA), SID(WD)})`,
		`(Not_Member_of_Any {SID(BA)})`,
		`(Exists @User.Title)`,
		`(Not_Exists @User.Title)`,
		`(!(@User.Title=="PM"))`,
		`(@User.count>=-5)`,
		`(@User.count==0x1f)`,
		`(@User.blob==#01ff2a)`,
		`(@User.dept Contains "Sales")`,
		`(@User.dept != {1, 2, 3})`,
	}

	for _, expr := range exprs {
		t.Run(expr, func(t *testing.T) {
			bin1, err := condition.Marshal(expr)
			if err != nil {
				t.Fatalf("Marshal(%q) error = %v", expr, err)
			}
			if !condition.IsConditional(bin1) {
				t.Fatalf("encoded data lacks the artx signature")
			}
			text, err := condition.Unmarshal(bin1)
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}
			bin2, err := condition.Marshal(text)
			if err != nil {
				t.Fatalf("re-Marshal(%q) error = %v", text, err)
			}
			if hex.EncodeToString(bin1) != hex.EncodeToString(bin2) {
				t.Fatalf("binary round-trip not stable for %q:\n  first:  %x\n  via %q\n  second: %x", expr, bin1, text, bin2)
			}
		})
	}
}

// TestParseErrors verifies malformed expressions are rejected.
func TestParseErrors(t *testing.T) {
	bad := []string{
		`(@User.Title ==)`,
		`(&& @User.Title=="x")`,
		`(@User.Title == "unterminated)`,
		`(Member_of SID(BA))`, // Member_of requires a brace array
		`()`,
	}
	for _, expr := range bad {
		t.Run(expr, func(t *testing.T) {
			if _, err := condition.Marshal(expr); err == nil {
				t.Fatalf("Marshal(%q) expected an error, got nil", expr)
			}
		})
	}
}

// TestIsConditional checks signature detection.
func TestIsConditional(t *testing.T) {
	if condition.IsConditional([]byte{0x00, 0x01, 0x02, 0x03}) {
		t.Error("non-artx data reported as conditional")
	}
	if !condition.IsConditional([]byte("artx....")) {
		t.Error("artx data not reported as conditional")
	}
	if condition.IsConditional([]byte{0x61, 0x72}) {
		t.Error("short data reported as conditional")
	}
}

// TestKeywordOperatorsAreCaseInsensitive checks that SDDL keyword operators parse
// regardless of case, and in particular that both capitalisations in circulation
// for the four "any" operators are accepted: MS-DTYP 2.4.4.17.6 spells them
// Member_of_Any, while the operator-name tables in Windows' own sechost.dll and
// advapi32.dll spell them Member_of_any.
//
// Each variant must encode to exactly the same bytes as the canonical spelling.
func TestKeywordOperatorsAreCaseInsensitive(t *testing.T) {
	cases := []struct {
		canonical string
		variants  []string
	}{
		// Unary membership operators.
		{`(Member_of {SID(BA)})`, []string{
			`(member_of {SID(BA)})`, `(MEMBER_OF {SID(BA)})`, `(MeMbEr_Of {SID(BA)})`}},
		{`(Device_Member_of {SID(BA)})`, []string{
			`(device_member_of {SID(BA)})`, `(DEVICE_MEMBER_OF {SID(BA)})`}},
		{`(Not_Member_of {SID(BA)})`, []string{`(not_member_of {SID(BA)})`}},
		{`(Not_Device_Member_of {SID(BA)})`, []string{`(NOT_DEVICE_MEMBER_OF {SID(BA)})`}},

		// The four operators Windows spells with a lowercase "any".
		{`(Member_of_Any {SID(BA)})`, []string{
			`(Member_of_any {SID(BA)})`, `(member_of_any {SID(BA)})`}},
		{`(Device_Member_of_Any {SID(BA)})`, []string{
			`(Device_Member_of_any {SID(BA)})`}},
		{`(Not_Member_of_Any {SID(BA)})`, []string{
			`(Not_Member_of_any {SID(BA)})`}},
		{`(Not_Device_Member_of_Any {SID(BA)})`, []string{
			`(Not_Device_Member_of_any {SID(BA)})`}},

		// Unary existence operators.
		{`(Exists @User.foo)`, []string{`(exists @User.foo)`, `(EXISTS @User.foo)`}},
		{`(Not_Exists @User.foo)`, []string{`(not_exists @User.foo)`, `(NOT_EXISTS @User.foo)`}},

		// Binary keyword operators, which are matched on the infix path.
		{`(@User.a Contains 1)`, []string{`(@User.a contains 1)`, `(@User.a CONTAINS 1)`}},
		{`(@User.a Not_Contains 1)`, []string{`(@User.a not_contains 1)`}},
		{`(@User.a Any_of {1,2})`, []string{`(@User.a any_of {1,2})`, `(@User.a ANY_OF {1,2})`}},
		{`(@User.a Not_Any_of {1,2})`, []string{`(@User.a not_any_of {1,2})`}},
	}

	for _, c := range cases {
		want, err := condition.Marshal(c.canonical)
		if err != nil {
			t.Fatalf("Marshal(%q) error = %v", c.canonical, err)
		}
		for _, variant := range c.variants {
			t.Run(variant, func(t *testing.T) {
				got, err := condition.Marshal(variant)
				if err != nil {
					t.Fatalf("Marshal(%q) error = %v", variant, err)
				}
				if hex.EncodeToString(got) != hex.EncodeToString(want) {
					t.Fatalf("Marshal(%q) = %s, want %s (same as %q)",
						variant, hex.EncodeToString(got), hex.EncodeToString(want), c.canonical)
				}
			})
		}
	}
}

// TestSerializeUsesSpecCapitalization pins the serialization direction: whatever
// case was parsed, the text form emitted uses the MS-DTYP capitalisation.
func TestSerializeUsesSpecCapitalization(t *testing.T) {
	raw, err := condition.Marshal(`(Member_of_any {SID(BA)})`)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	got, err := condition.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !strings.Contains(got, "Member_of_Any") {
		t.Fatalf("Unmarshal() = %q, want it to contain %q", got, "Member_of_Any")
	}
}

// TestUnaryKeywordOperatorsRejectedInInfixPosition guards the infix path against
// admitting the unary operators: only Contains/Not_Contains/Any_of/Not_Any_of may
// appear between a left- and right-hand side.
func TestUnaryKeywordOperatorsRejectedInInfixPosition(t *testing.T) {
	bad := []string{
		`(@User.a Member_of {SID(BA)})`,
		`(@User.a member_of {SID(BA)})`,
		`(@User.a Exists @User.b)`,
		`(@User.a exists @User.b)`,
	}
	for _, expr := range bad {
		t.Run(expr, func(t *testing.T) {
			if _, err := condition.Marshal(expr); err == nil {
				t.Fatalf("Marshal(%q) expected an error, got nil", expr)
			}
		})
	}
}

// TestTokenAttribute_0xfc covers the fifth attribute token, 0xfc, whose SDDL
// prefix is "@TOKEN.". MS-DTYP 2.4.4.17.8 documents only 0xf8-0xfb and its
// 2.5.1.1 ABNF admits only @user./@device./@resource., but Windows implements
// 0xfc in both directions: sechost.dll and advapi32.dll parse "@TOKEN." into
// 0xfc and render 0xfc back to "@TOKEN.", and the kernel evaluator gives it its
// own attribute source class.
//
// Its wire encoding is identical to the other attribute tokens: the token byte,
// a DWORD byte length, then the UTF-16 name.
func TestTokenAttribute_0xfc(t *testing.T) {
	// The token byte lands where the other attribute tokens do: straight after
	// the 4-byte "artx" signature for a leading attribute operand.
	raw, err := condition.Marshal(`(@TOKEN.foo == 1)`)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if len(raw) < 5 {
		t.Fatalf("encoded condition too short: %s", hex.EncodeToString(raw))
	}
	if raw[4] != 0xfc {
		t.Fatalf("attribute token = 0x%02x, want 0xfc (encoded: %s)", raw[4], hex.EncodeToString(raw))
	}

	// Serialization uses this package's existing capitalisation convention,
	// matching @User./@Device./@Resource. rather than Windows' all-caps form.
	got, err := condition.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got != `@Token.foo == 1` {
		t.Fatalf("Unmarshal() = %q, want %q", got, `@Token.foo == 1`)
	}
}

// TestTokenAttribute_PrefixIsCaseInsensitive checks that the @TOKEN. prefix folds
// case like the three documented prefixes, and that every casing yields token 0xfc.
func TestTokenAttribute_PrefixIsCaseInsensitive(t *testing.T) {
	for _, expr := range []string{
		`(@TOKEN.foo == 1)`, `(@token.foo == 1)`, `(@Token.foo == 1)`, `(@ToKeN.foo == 1)`,
	} {
		t.Run(expr, func(t *testing.T) {
			raw, err := condition.Marshal(expr)
			if err != nil {
				t.Fatalf("Marshal(%q) error = %v", expr, err)
			}
			if raw[4] != 0xfc {
				t.Fatalf("attribute token = 0x%02x, want 0xfc", raw[4])
			}
		})
	}
}

// TestTokenAttribute_DecodeWindowsBlob decodes a hand-assembled payload of the
// shape Windows produces — 0xfc, DWORD length, UTF-16 name — proving the decoder
// no longer rejects the token. Before this was supported, Unmarshal failed with
// "unknown conditional-expression token 0xfc".
func TestTokenAttribute_DecodeWindowsBlob(t *testing.T) {
	// artx | 0xfc len=6 "foo" | 0x04 int64(1) sign=none base=dec | 0x80 == | pad
	blob, err := hex.DecodeString(
		"61727478" + "fc06000000" + "66006f006f00" +
			"04" + "0100000000000000" + "0302" + "80" + "00")
	if err != nil {
		t.Fatalf("bad test vector: %v", err)
	}
	got, err := condition.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got != `@Token.foo == 1` {
		t.Fatalf("Unmarshal() = %q, want %q", got, `@Token.foo == 1`)
	}
}

// TestTokenAttribute_RoundTripStable checks Marshal -> Unmarshal -> Marshal is
// byte-stable for 0xfc across operand positions and operator kinds, and that it
// composes with the documented attribute tokens.
func TestTokenAttribute_RoundTripStable(t *testing.T) {
	for _, expr := range []string{
		`(@Token.foo == 1)`,
		`(@Token.dept == "eng")`,
		`(@Token.a == @Token.b)`,
		`(@Token.a Any_of {1, 2})`,
		`(@Token.a && @User.b)`,
		`(@Token.flags == 0x10)`,
		`(Exists @Token.foo)`,
	} {
		t.Run(expr, func(t *testing.T) {
			first, err := condition.Marshal(expr)
			if err != nil {
				t.Fatalf("Marshal(%q) error = %v", expr, err)
			}
			text, err := condition.Unmarshal(first)
			if err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			second, err := condition.Marshal("(" + text + ")")
			if err != nil {
				t.Fatalf("re-Marshal(%q) error = %v", text, err)
			}
			if hex.EncodeToString(first) != hex.EncodeToString(second) {
				t.Fatalf("round-trip not byte-stable:\n first  = %s\n second = %s",
					hex.EncodeToString(first), hex.EncodeToString(second))
			}
		})
	}
}

// TestTokenAttribute_NotAliasOfUserAttr guards against implementing @TOKEN. as a
// synonym for @USER.. They are separate tokens with separate value sources: the
// kernel evaluator reads 0xfc from the access token and 0xf9 from the user-claims
// collection, and assigns them different internal source classes.
func TestTokenAttribute_NotAliasOfUserAttr(t *testing.T) {
	tokenRaw, err := condition.Marshal(`(@Token.foo == 1)`)
	if err != nil {
		t.Fatalf("Marshal(@Token.) error = %v", err)
	}
	userRaw, err := condition.Marshal(`(@User.foo == 1)`)
	if err != nil {
		t.Fatalf("Marshal(@User.) error = %v", err)
	}
	if tokenRaw[4] == userRaw[4] {
		t.Fatalf("@Token. and @User. encoded to the same token 0x%02x; they must differ", tokenRaw[4])
	}
	if userRaw[4] != 0xf9 {
		t.Fatalf("@User. token = 0x%02x, want 0xf9", userRaw[4])
	}
	if text, _ := condition.Unmarshal(userRaw); text != `@User.foo == 1` {
		t.Fatalf("@User. round-trip = %q, want %q", text, `@User.foo == 1`)
	}
}

// TestBitwiseAnd_0xa3 covers the undocumented '&' operator, token 0xa3. Neither
// MS-DTYP's relational table (2.4.4.17.6, which stops at 0x93) nor its logical
// table (2.4.4.17.7, which defines only 0xa0/0xa1/0xa2) lists it, and the 2.5.1.1
// ABNF has "&&" but never a lone "&". Windows implements it in all three copies of
// the operator table (sechost.dll, advapi32.dll, ntoskrnl.exe) and the kernel
// evaluator computes a bitwise AND of two 64-bit integers, TRUE when non-zero.
func TestBitwiseAnd_0xa3(t *testing.T) {
	raw, err := condition.Marshal(`(@User.flags & 4)`)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	// Postfix: the operator is the last non-padding byte.
	end := len(raw)
	for end > 0 && raw[end-1] == 0x00 {
		end--
	}
	if end == 0 || raw[end-1] != 0xa3 {
		t.Fatalf("trailing operator byte = 0x%02x, want 0xa3 (encoded: %s)",
			raw[end-1], hex.EncodeToString(raw))
	}
	got, err := condition.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got != `@User.flags & 4` {
		t.Fatalf("Unmarshal() = %q, want %q", got, `@User.flags & 4`)
	}
}

// TestBitwiseAnd_FlagTestForms exercises the operand shapes '&' actually takes: a
// value-bearing left side with a literal or attribute on the right. These are the
// forms a flag test uses, and the reason '&' is parsed as a binary relational
// operator rather than alongside && and ||.
func TestBitwiseAnd_FlagTestForms(t *testing.T) {
	for _, expr := range []string{
		`(@User.a & 1)`,
		`(@Resource.flags & 4)`,
		`(@User.flags & 0x10)`,
		`(@User.a & @User.b)`,
		`(flags & 3)`,
		// Both undocumented constructs in one expression: the 0xfc attribute
		// token as the left operand of the 0xa3 operator.
		`(@Token.flags & 8)`,
	} {
		t.Run(expr, func(t *testing.T) {
			first, err := condition.Marshal(expr)
			if err != nil {
				t.Fatalf("Marshal(%q) error = %v", expr, err)
			}
			text, err := condition.Unmarshal(first)
			if err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			second, err := condition.Marshal("(" + text + ")")
			if err != nil {
				t.Fatalf("re-Marshal(%q) error = %v", text, err)
			}
			if hex.EncodeToString(first) != hex.EncodeToString(second) {
				t.Fatalf("round-trip not byte-stable:\n first  = %s\n second = %s",
					hex.EncodeToString(first), hex.EncodeToString(second))
			}
		})
	}
}

// TestBitwiseAnd_LogicalOperandRoundTrips is the regression test for the tree
// Windows' own parser can build but this package's text grammar does not produce.
// Because '&' has precedence 10 there — below || (11) and && (12) — Windows groups
// "a & b || c" as "a & (b || c)", giving a '&' whose right operand is a logical
// expression. The binary form encodes that unambiguously in postfix, so decoding
// must yield parenthesized text that re-encodes to the identical bytes.
func TestBitwiseAnd_LogicalOperandRoundTrips(t *testing.T) {
	// artx | @User.a | @User.b | @User.c | 0xa1 (||) | 0xa3 (&) | pad
	blob, err := hex.DecodeString(
		"61727478" +
			"f902000000" + "6100" +
			"f902000000" + "6200" +
			"f902000000" + "6300" +
			"a1" + "a3" + "00")
	if err != nil {
		t.Fatalf("bad test vector: %v", err)
	}
	text, err := condition.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	const want = `@User.a & (@User.b || @User.c)`
	if text != want {
		t.Fatalf("Unmarshal() = %q, want %q", text, want)
	}
	again, err := condition.Marshal("(" + text + ")")
	if err != nil {
		t.Fatalf("re-Marshal(%q) error = %v", text, err)
	}
	if hex.EncodeToString(again) != hex.EncodeToString(blob) {
		t.Fatalf("re-encode differs:\n want = %s\n got  = %s",
			hex.EncodeToString(blob), hex.EncodeToString(again))
	}
}

// TestBitwiseAnd_DoesNotShadowLogicalAnd checks the lexer still matches "&&"
// before a lone "&", so logical AND keeps token 0xa0.
func TestBitwiseAnd_DoesNotShadowLogicalAnd(t *testing.T) {
	andRaw, err := condition.Marshal(`(@User.a == 1 && @User.b == 2)`)
	if err != nil {
		t.Fatalf("Marshal(&&) error = %v", err)
	}
	if got, _ := condition.Unmarshal(andRaw); got != `@User.a == 1 && @User.b == 2` {
		t.Fatalf("&& round-trip = %q", got)
	}
	if !strings.Contains(hex.EncodeToString(andRaw), "a0") {
		t.Fatalf("logical AND did not encode token 0xa0: %s", hex.EncodeToString(andRaw))
	}
	// A lone '&' must not be accepted where a logical operand is required, since
	// its operands are values.
	if _, err := condition.Marshal(`(Member_of {SID(BA)} & Member_of {SID(WD)})`); err == nil {
		t.Fatal("expected an error for '&' applied to Member_of results (not integer operands)")
	}
}

// TestBitwiseAnd_ParenthesizedRHSOnlyForBitwiseAnd pins that the widened
// right-hand-side grammar is scoped to '&' and does not leak to the other
// relational operators.
func TestBitwiseAnd_ParenthesizedRHSOnlyForBitwiseAnd(t *testing.T) {
	if _, err := condition.Marshal(`(@User.a & (@User.b || @User.c))`); err != nil {
		t.Fatalf("'&' with a parenthesized RHS should parse, got %v", err)
	}
	for _, expr := range []string{
		`(@User.a == (@User.b || @User.c))`,
		`(@User.a < (@User.b && @User.c))`,
	} {
		if _, err := condition.Marshal(expr); err == nil {
			t.Errorf("%q should not parse: only '&' accepts a parenthesized RHS", expr)
		}
	}
}
