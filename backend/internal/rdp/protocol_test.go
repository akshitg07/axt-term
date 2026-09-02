package rdp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestEncodeRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		opcode string
		args   []string
	}{
		{name: "no args", opcode: "nop"},
		{name: "one arg", opcode: "sync", args: []string{"31415"}},
		{name: "several args", opcode: "mouse", args: []string{"640", "480", "1"}},
		{name: "empty args", opcode: "connect", args: []string{"", "", "value", ""}},
		{name: "separators inside values", opcode: "clipboard", args: []string{"a,b;c.d"}},
		{name: "newlines inside values", opcode: "blob", args: []string{"line one\nline two"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := Encode(tc.opcode, tc.args...)

			got, err := Decode(encoded)
			if err != nil {
				t.Fatalf("Decode(%q) returned %v", encoded, err)
			}
			if got.Opcode != tc.opcode {
				t.Errorf("opcode = %q, want %q", got.Opcode, tc.opcode)
			}
			if len(got.Args) != len(tc.args) {
				t.Fatalf("got %d args, want %d: %#v", len(got.Args), len(tc.args), got.Args)
			}
			for i := range tc.args {
				if got.Args[i] != tc.args[i] {
					t.Errorf("arg %d = %q, want %q", i, got.Args[i], tc.args[i])
				}
			}
		})
	}
}

// TestLengthPrefixCountsUTF16CodeUnits pins the subtlest rule in the codec.
//
// The Guacamole length prefix counts characters the way both reference
// implementations count them: Java's String.length() and JavaScript's
// String.length, which are UTF-16 code units. Counting bytes desynchronises the
// stream on the first accented character; counting runes desynchronises on the
// first emoji, which is one rune but two code units. Either failure looks like a
// corrupt display rather than an encoding bug, so it is worth pinning precisely.
func TestLengthPrefixCountsUTF16CodeUnits(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  int
	}{
		{name: "ascii", value: "hello", want: 5},
		{name: "empty", value: "", want: 0},
		{name: "latin with accents", value: "café", want: 4},
		{name: "cyrillic", value: "привет", want: 6},
		{name: "cjk", value: "日本語", want: 3},
		// Outside the BMP: one rune, four UTF-8 bytes, two UTF-16 code units.
		{name: "emoji", value: "😀", want: 2},
		{name: "emoji among ascii", value: "a😀b", want: 4},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := utf16Len(tc.value); got != tc.want {
				t.Errorf("utf16Len(%q) = %d, want %d", tc.value, got, tc.want)
			}

			// The encoded form must declare that same count on the wire.
			encoded := string(Encode("clipboard", tc.value))
			wantPrefix := "9.clipboard," + itoa(tc.want) + "."
			if !strings.HasPrefix(encoded, wantPrefix) {
				t.Errorf("encoded %q does not start with %q", encoded, wantPrefix)
			}

			// And it must survive a round trip byte for byte.
			got, err := Decode([]byte(encoded))
			if err != nil {
				t.Fatalf("Decode returned %v", err)
			}
			if got.Arg(0) != tc.value {
				t.Errorf("round trip gave %q, want %q", got.Arg(0), tc.value)
			}
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestReadInstructionSequence(t *testing.T) {
	stream := "3.nop;4.sync,5.31415;5.error,7.oh dear,3.512;"
	r := NewReader(strings.NewReader(stream))

	first, err := r.ReadInstruction()
	if err != nil || first.Opcode != "nop" {
		t.Fatalf("first = %#v, err = %v", first, err)
	}
	second, err := r.ReadInstruction()
	if err != nil || second.Opcode != "sync" || second.Arg(0) != "31415" {
		t.Fatalf("second = %#v, err = %v", second, err)
	}
	third, err := r.ReadInstruction()
	if err != nil || third.Opcode != "error" || third.Arg(1) != "512" {
		t.Fatalf("third = %#v, err = %v", third, err)
	}

	// A stream that ends between instructions is a clean close, not a fault.
	if _, err := r.ReadInstruction(); !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF at end of stream, got %v", err)
	}
}

func TestReadInstructionRejectsMalformed(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  error
	}{
		{name: "truncated mid value", input: "5.erro", want: ErrMalformed},
		{name: "missing terminator", input: "3.nop", want: ErrMalformed},
		{name: "no length prefix", input: "nop;", want: ErrMalformed},
		{name: "empty length prefix", input: ".nop;", want: ErrMalformed},
		{name: "wrong separator", input: "3.nop!", want: ErrMalformed},
		{name: "length longer than value", input: "9.nop;", want: ErrMalformed},
		{name: "invalid utf8", input: "1.\xff;", want: ErrMalformed},
		{name: "absurd length prefix", input: "99999999999.x;", want: ErrTooLarge},
		{name: "element larger than the cap", input: "2000000.x;", want: ErrTooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(strings.NewReader(tc.input))
			_, err := r.ReadInstruction()
			if !errors.Is(err, tc.want) {
				t.Errorf("ReadInstruction(%q) returned %v, want %v", tc.input, err, tc.want)
			}
		})
	}
}

// TestReadInstructionRejectsSplitSurrogatePair covers a value whose declared
// length falls in the middle of an astral character. A sender that counted runes
// would produce exactly this, and accepting it would shift every following
// instruction.
func TestReadInstructionRejectsSplitSurrogatePair(t *testing.T) {
	r := NewReader(strings.NewReader("1.😀;"))
	if _, err := r.ReadInstruction(); !errors.Is(err, ErrMalformed) {
		t.Errorf("expected ErrMalformed for a length that splits a surrogate pair, got %v", err)
	}
}

func TestReadInstructionRejectsTooManyElements(t *testing.T) {
	var b strings.Builder
	b.WriteString("3.nop")
	for i := 0; i <= MaxElements; i++ {
		b.WriteString(",1.x")
	}
	b.WriteString(";")

	r := NewReader(strings.NewReader(b.String()))
	if _, err := r.ReadInstruction(); !errors.Is(err, ErrTooManyArgs) {
		t.Errorf("expected ErrTooManyArgs, got %v", err)
	}
}

func TestDecodeRejectsTrailingInstruction(t *testing.T) {
	// One frame must carry exactly one instruction. Accepting a second would be a
	// way to smuggle a disallowed opcode past the allow-list, which only ever
	// inspects the first.
	_, err := Decode([]byte("3.nop;7.connect,1.x;"))
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("expected ErrMalformed for two instructions in one frame, got %v", err)
	}
}

func TestWriterSerialisesInstructions(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.Write("select", "rdp"); err != nil {
		t.Fatalf("Write returned %v", err)
	}
	if err := w.Write("size", "1024", "768", "96"); err != nil {
		t.Fatalf("Write returned %v", err)
	}

	want := "6.select,3.rdp;4.size,4.1024,3.768,2.96;"
	if got := buf.String(); got != want {
		t.Errorf("wrote %q, want %q", got, want)
	}
}

func TestInstructionStringOmitsArgumentValues(t *testing.T) {
	// The `connect` instruction carries every credential we hold. A String method
	// that included values would put them in the first log line somebody added
	// while debugging a failed connection.
	in := Instruction{Opcode: "connect", Args: []string{"10.0.0.5", "3389", "administrator", "hunter2"}}

	got := in.String()
	if strings.Contains(got, "hunter2") || strings.Contains(got, "administrator") {
		t.Errorf("Instruction.String() leaked argument values: %q", got)
	}
	if got != "connect/4" {
		t.Errorf("Instruction.String() = %q, want %q", got, "connect/4")
	}
}

func TestAllowedFromClient(t *testing.T) {
	cases := []struct {
		opcode string
		drive  bool
		want   bool
	}{
		// Normal input and stream traffic.
		{opcode: "key", want: true},
		{opcode: "mouse", want: true},
		{opcode: "touch", want: true},
		{opcode: "size", want: true},
		{opcode: "clipboard", want: true},
		{opcode: "blob", want: true},
		{opcode: "end", want: true},
		{opcode: "ack", want: true},
		{opcode: "sync", want: true},
		{opcode: "disconnect", want: true},

		// Handshake opcodes. A client able to send these could choose the
		// connection's parameters, which is the property ADR 0003 exists to deny.
		{opcode: "select", want: false},
		{opcode: "connect", want: false},
		{opcode: "image", want: false},
		{opcode: "audio", want: false},
		{opcode: "video", want: false},
		{opcode: "timezone", want: false},

		// Drive redirection is per-host opt-in, on the instruction as well as the
		// handshake parameter.
		{opcode: "get", drive: false, want: false},
		{opcode: "put", drive: false, want: false},
		{opcode: "get", drive: true, want: true},
		{opcode: "put", drive: true, want: true},

		{opcode: "invented", want: false},
		{opcode: "", want: false},
	}

	for _, tc := range cases {
		name := tc.opcode
		if name == "" {
			name = "empty"
		}
		if tc.drive {
			name += "+drive"
		}
		t.Run(name, func(t *testing.T) {
			if got := AllowedFromClient(tc.opcode, tc.drive); got != tc.want {
				t.Errorf("AllowedFromClient(%q, drive=%v) = %v, want %v",
					tc.opcode, tc.drive, got, tc.want)
			}
		})
	}
}
