// Package rdp is the Guacamole protocol client: handshake, instruction codec,
// and relay between guacd and the browser.
//
// The backend is a full Guacamole protocol participant rather than a dumb pipe.
// That is the point of ADR 0003: because we perform the handshake, connection
// parameters -- including decrypted credentials -- are assembled server-side and
// travel only on the backend->guacd hop across a private network. The browser
// receives a single-use WebSocket ticket and an instruction stream, never a
// password and never a hostname it could tamper with.
package rdp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Codec errors. All are returned wrapped with position detail; callers treat any
// of them as fatal for the connection, because a desynchronised instruction
// stream cannot be resynchronised -- there is no framing to resynchronise to.
var (
	ErrMalformed   = errors.New("rdp: malformed guacamole instruction")
	ErrTooLarge    = errors.New("rdp: guacamole instruction exceeds the size limit")
	ErrTooManyArgs = errors.New("rdp: guacamole instruction has too many elements")
)

// Relay limits.
//
// ADR 0003 requires the relay to bound what a hostile or malfunctioning daemon
// can make the backend allocate. These are deliberately generous -- a single
// `blob` carrying a screen region of JPEG is tens of kilobytes, and `img` streams
// for a 4K desktop are larger still -- while still being a bound.
const (
	// MaxInstructionLen caps one complete instruction, in UTF-16 code units
	// summed across its elements.
	MaxInstructionLen = 1 << 20

	// MaxElements caps the element count of one instruction. Real instructions
	// top out in the low tens; `connect` is the longest, one element per
	// parameter guacd declared.
	MaxElements = 256
)

// Instruction is one Guacamole protocol instruction.
//
// The wire format is `LENGTH.VALUE,LENGTH.VALUE,...;` -- for example
// `5.error,9.Some text,1.0;`. Opcode is the first element and Args the rest,
// split out here because every caller wants that distinction.
type Instruction struct {
	Opcode string
	Args   []string
}

// Arg returns the argument at index i, or the empty string when it is absent.
//
// guacd's instruction arity varies by version, so indexing defensively is the
// difference between tolerating a new field and panicking on it.
func (in Instruction) Arg(i int) string {
	if i < 0 || i >= len(in.Args) {
		return ""
	}
	return in.Args[i]
}

// String renders the instruction for logging.
//
// Deliberately opcode-and-arity only. Instructions carry clipboard contents,
// window titles, and -- in the case of `connect` -- every credential we hold, so
// a String that included argument values would defeat the whole point of
// assembling parameters server-side. See also params.go, which is why no
// parameter map in this package has a String method either.
func (in Instruction) String() string {
	return fmt.Sprintf("%s/%d", in.Opcode, len(in.Args))
}

// utf16Len returns the length of s in UTF-16 code units.
//
// This is the single subtlest detail in the codec. The Guacamole protocol's
// length prefix counts *characters* as both reference implementations count them:
// guacamole-common (Java) uses String.length() and guacamole-common-js uses
// JavaScript's String.length, and both of those are UTF-16 code units. Counting
// bytes would work for ASCII and then desynchronise the stream the first time a
// window title or a clipboard paste contained an accented letter; counting runes
// would work until the first emoji, which is one rune but two code units.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// Encode renders an instruction onto the wire.
func Encode(opcode string, args ...string) []byte {
	var b strings.Builder
	// A rough reservation: every element pays its own length prefix and separator.
	b.Grow(len(opcode) + 8 + len(args)*16)

	writeElement(&b, opcode)
	for _, arg := range args {
		b.WriteByte(',')
		writeElement(&b, arg)
	}
	b.WriteByte(';')
	return []byte(b.String())
}

func writeElement(b *strings.Builder, value string) {
	b.WriteString(strconv.Itoa(utf16Len(value)))
	b.WriteByte('.')
	b.WriteString(value)
}

// Encode renders the instruction onto the wire.
func (in Instruction) Encode() []byte { return Encode(in.Opcode, in.Args...) }

// Reader parses instructions from a stream.
//
// Not safe for concurrent use: one goroutine owns the read side of a guacd
// connection, exactly as one goroutine owns the read side of a WebSocket.
type Reader struct {
	br *bufio.Reader
}

// NewReader wraps r.
func NewReader(r io.Reader) *Reader {
	return &Reader{br: bufio.NewReaderSize(r, 64*1024)}
}

// ReadInstruction reads one complete instruction.
//
// It returns io.EOF only when the stream ends cleanly between instructions; a
// stream that ends mid-instruction is ErrMalformed, because silently treating a
// truncated instruction as end-of-stream would turn a network fault into what
// looks like an orderly disconnect.
func (r *Reader) ReadInstruction() (Instruction, error) {
	var (
		elements []string
		total    int
	)

	for {
		length, err := r.readLength(len(elements) == 0)
		if err != nil {
			return Instruction{}, err
		}

		total += length
		if total > MaxInstructionLen {
			return Instruction{}, fmt.Errorf("%w: %d code units", ErrTooLarge, total)
		}

		value, err := r.readValue(length)
		if err != nil {
			return Instruction{}, err
		}
		elements = append(elements, value)
		if len(elements) > MaxElements {
			return Instruction{}, fmt.Errorf("%w: %d", ErrTooManyArgs, len(elements))
		}

		// The separator decides whether the instruction continues or ends.
		sep, err := r.br.ReadByte()
		if err != nil {
			return Instruction{}, fmt.Errorf("%w: truncated after element %d: %w",
				ErrMalformed, len(elements), err)
		}
		switch sep {
		case ',':
			continue
		case ';':
			return Instruction{Opcode: elements[0], Args: elements[1:]}, nil
		default:
			return Instruction{}, fmt.Errorf("%w: expected ',' or ';' after element %d, got %q",
				ErrMalformed, len(elements), sep)
		}
	}
}

// readLength reads the decimal length prefix and consumes the '.' after it.
//
// first distinguishes the opcode's prefix, where a clean EOF means the stream
// ended between instructions and is reported as io.EOF unwrapped.
func (r *Reader) readLength(first bool) (int, error) {
	digits := make([]byte, 0, 8)
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && first && len(digits) == 0 {
				return 0, io.EOF
			}
			return 0, fmt.Errorf("%w: truncated length prefix: %w", ErrMalformed, err)
		}
		if b == '.' {
			break
		}
		if b < '0' || b > '9' {
			return 0, fmt.Errorf("%w: non-digit %q in length prefix", ErrMalformed, b)
		}
		digits = append(digits, b)
		// Guard the parse itself: without this a daemon could send an arbitrarily
		// long run of digits and make us buffer it.
		if len(digits) > 10 {
			return 0, fmt.Errorf("%w: length prefix too long", ErrTooLarge)
		}
	}
	if len(digits) == 0 {
		return 0, fmt.Errorf("%w: empty length prefix", ErrMalformed)
	}

	length, err := strconv.Atoi(string(digits))
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if length > MaxInstructionLen {
		return 0, fmt.Errorf("%w: element declares %d code units", ErrTooLarge, length)
	}
	return length, nil
}

// readValue reads exactly length UTF-16 code units and returns them as UTF-8.
func (r *Reader) readValue(length int) (string, error) {
	if length == 0 {
		return "", nil
	}

	var b strings.Builder
	b.Grow(length)

	for units := 0; units < length; {
		ru, size, err := r.br.ReadRune()
		if err != nil {
			return "", fmt.Errorf("%w: truncated element value: %w", ErrMalformed, err)
		}
		// ReadRune reports invalid UTF-8 as RuneError with size 1. Accepting it
		// would silently corrupt the value and, worse, miscount the length.
		if ru == utf8.RuneError && size == 1 {
			return "", fmt.Errorf("%w: invalid UTF-8 in element value", ErrMalformed)
		}

		cost := 1
		if ru > 0xFFFF {
			cost = 2
		}
		if units+cost > length {
			// A surrogate pair straddling the declared length means the sender
			// counted differently than the protocol specifies.
			return "", fmt.Errorf("%w: element value does not align with its declared length",
				ErrMalformed)
		}
		b.WriteRune(ru)
		units += cost
	}
	return b.String(), nil
}

// Writer serialises instructions onto a stream.
//
// Writes are mutex-guarded because two goroutines legitimately write to the same
// guacd connection: the relay forwarding browser input, and the session echoing
// `sync` to keep guacd's flow control satisfied while no viewer is attached.
type Writer struct {
	mu sync.Mutex
	bw *bufio.Writer
}

// NewWriter wraps w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{bw: bufio.NewWriterSize(w, 16*1024)}
}

// Write sends one instruction and flushes it.
//
// Flushing per instruction is deliberate: an instruction held in a buffer is an
// input event the desktop has not seen, and interactive latency matters far more
// here than syscall count.
func (w *Writer) Write(opcode string, args ...string) error {
	return w.WriteRaw(Encode(opcode, args...))
}

// WriteRaw sends an already-encoded instruction.
//
// Used by the relay, which forwards the browser's instructions verbatim after
// validating their opcode rather than decoding and re-encoding them.
func (w *Writer) WriteRaw(encoded []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.bw.Write(encoded); err != nil {
		return err
	}
	return w.bw.Flush()
}

// Decode parses a single complete instruction from b.
//
// Used on the browser's frames, which arrive one instruction per WebSocket frame.
// Trailing bytes are rejected: a frame carrying a second, unexamined instruction
// would be a way to smuggle an opcode past the allow-list below.
func Decode(b []byte) (Instruction, error) {
	r := NewReader(bytes.NewReader(b))
	in, err := r.ReadInstruction()
	if err != nil {
		return Instruction{}, err
	}
	if _, err := r.br.ReadByte(); !errors.Is(err, io.EOF) {
		return Instruction{}, fmt.Errorf("%w: frame carries more than one instruction", ErrMalformed)
	}
	return in, nil
}

// clientOpcodes are the instructions a browser may send.
//
// An allow-list, not a deny-list. The handshake opcodes are the reason: `select`
// and `connect` are how a connection's parameters are chosen, and a client able to
// send them mid-stream could try to open a connection to a host of its choosing
// with parameters of its choosing -- which is precisely the property ADR 0003
// exists to prevent by keeping parameter assembly server-side. `image`, `audio`,
// `video`, and `timezone` are likewise handshake-only and already sent on the
// browser's behalf.
var clientOpcodes = map[string]bool{
	"key":        true,
	"mouse":      true,
	"touch":      true,
	"size":       true,
	"clipboard":  true,
	"blob":       true,
	"end":        true,
	"ack":        true,
	"sync":       true,
	"nop":        true,
	"argv":       true,
	"disconnect": true,
}

// driveOpcodes additionally require drive redirection to be enabled for the host.
//
// These open file streams towards the target. Drive redirection is per-host opt-in
// (ADR 0003), and the gate belongs on the instruction as well as the handshake
// parameter: guacd would honour a `put` even if we never asked it to share a drive.
var driveOpcodes = map[string]bool{
	"get": true,
	"put": true,
}

// AllowedFromClient reports whether the browser may send this opcode.
func AllowedFromClient(opcode string, driveEnabled bool) bool {
	if clientOpcodes[opcode] {
		return true
	}
	if driveOpcodes[opcode] {
		return driveEnabled
	}
	return false
}
