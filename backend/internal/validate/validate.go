// Package validate holds the input rules shared across the API.
//
// Validation is centralised per value type rather than repeated per handler, so
// the create and update paths for a resource cannot drift apart -- which is how
// one endpoint ends up accepting something another rejects.
package validate

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Field describes one validation failure, matching the API's error details shape.
type Field struct {
	Name    string
	Message string
}

// Errors accumulates field failures so a request reports every problem at once.
type Errors struct {
	fields []Field
}

// Add records a failure.
func (e *Errors) Add(name, message string) {
	e.fields = append(e.fields, Field{Name: name, Message: message})
}

// Check records err against a field when err is non-nil.
func (e *Errors) Check(name string, err error) {
	if err != nil {
		e.Add(name, err.Error())
	}
}

// Any reports whether anything failed.
func (e *Errors) Any() bool { return len(e.fields) > 0 }

// Map renders the failures for the API error envelope.
func (e *Errors) Map() map[string]any {
	out := make(map[string]any, len(e.fields))
	for _, f := range e.fields {
		// First failure per field wins; a second message for the same field is
		// almost always a consequence of the first.
		if _, exists := out[f.Name]; !exists {
			out[f.Name] = f.Message
		}
	}
	return out
}

// Error renders the failures as text, for CLI use.
func (e *Errors) Error() string {
	parts := make([]string, 0, len(e.fields))
	for _, f := range e.fields {
		parts = append(parts, f.Name+": "+f.Message)
	}
	return strings.Join(parts, "; ")
}

var (
	// hostnamePattern accepts DNS names, including single-label internal names.
	hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$`)

	// unitPattern matches systemd unit names. Anchored and narrow, because this
	// value reaches a remote command line: a unit name is the one field where a
	// permissive pattern would be an injection.
	unitPattern = regexp.MustCompile(`^[A-Za-z0-9@:._\-]{1,255}\.(service|socket|timer|target|mount|path|slice|scope)$`)

	pidPattern      = regexp.MustCompile(`^[0-9]{1,7}$`)
	modePattern     = regexp.MustCompile(`^0?[0-7]{3,4}$`)
	variablePattern = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,63}$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	colorPattern    = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	tagPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._\-]{0,63}$`)
	usernamePattern = regexp.MustCompile(`^[A-Za-z0-9._\-]{1,64}$`)
)

// Hostname checks a DNS name or IP literal.
func Hostname(s string) error {
	if s == "" {
		return errors.New("required")
	}
	if len(s) > 253 {
		return errors.New("must be at most 253 characters")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	if !hostnamePattern.MatchString(s) {
		return errors.New("must be a valid hostname or IP address")
	}
	return nil
}

// Port checks a TCP or UDP port.
func Port(n int) error {
	if n < 1 || n > 65535 {
		return errors.New("must be between 1 and 65535")
	}
	return nil
}

// Username checks an account name for a remote host.
func Username(s string) error {
	if s == "" {
		return nil // optional; the credential may supply it
	}
	if !usernamePattern.MatchString(s) {
		return errors.New("may contain only letters, digits, dot, underscore, and hyphen")
	}
	return nil
}

// UnitName checks a systemd unit name before it reaches a command line.
func UnitName(s string) error {
	if s == "" {
		return errors.New("required")
	}
	if !unitPattern.MatchString(s) {
		return errors.New("must be a systemd unit name such as nginx.service")
	}
	return nil
}

// PID checks a process identifier before it reaches a command line.
func PID(s string) (int, error) {
	if !pidPattern.MatchString(s) {
		return 0, errors.New("must be a numeric process id")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, errors.New("must be a numeric process id")
	}
	if n <= 0 {
		return 0, errors.New("must be a positive process id")
	}
	// PID 1 is init. Signalling it from a GUI is almost never intended and is
	// catastrophic when it is not; the Services panel is the correct route to
	// changing system state.
	if n == 1 {
		return 0, errors.New("refusing to target PID 1 (init); use the Services panel to manage system state")
	}
	return n, nil
}

// FileMode checks an octal permission string and returns it normalised.
func FileMode(s string) (uint32, error) {
	if !modePattern.MatchString(s) {
		return 0, errors.New("must be an octal mode such as 0644")
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, errors.New("must be an octal mode such as 0644")
	}
	return uint32(n), nil
}

// VariableName checks a snippet placeholder name.
func VariableName(s string) error {
	if !variablePattern.MatchString(s) {
		return errors.New("must start with a letter or underscore and contain only lowercase letters, digits, and underscores")
	}
	return nil
}

// UUID checks an identifier.
func UUID(s string) error {
	if !uuidPattern.MatchString(s) {
		return errors.New("must be a UUID")
	}
	return nil
}

// Color checks a hex colour.
func Color(s string) error {
	if s == "" {
		return nil
	}
	if !colorPattern.MatchString(s) {
		return errors.New("must be a hex colour such as #22d3ee")
	}
	return nil
}

// Tag checks a tag name.
func Tag(s string) error {
	if !tagPattern.MatchString(s) {
		return errors.New("must be 1 to 64 characters of letters, digits, space, dot, underscore, or hyphen")
	}
	return nil
}

// isBidiControl reports whether r is a bidirectional formatting character.
//
// These are Unicode category Cf rather than Cc, so unicode.IsControl does not
// catch them. They reorder how text renders without changing its bytes, which
// lets a crafted host name display as something entirely different in a list --
// including making a production host look like a staging one.
func isBidiControl(r rune) bool {
	switch r {
	case 0x200E, 0x200F, // left-to-right and right-to-left marks
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // embedding, pop, overrides
		0x2066, 0x2067, 0x2068, 0x2069: // isolates and pop
		return true
	}
	return false
}

// Name checks a display name for a host, folder, credential, or snippet.
func Name(s string, max int) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("required")
	}
	if !utf8.ValidString(s) {
		return errors.New("must be valid UTF-8")
	}
	if utf8.RuneCountInString(s) > max {
		return fmt.Errorf("must be at most %d characters", max)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return errors.New("must not contain control characters")
		}
		if isBidiControl(r) {
			return errors.New("must not contain bidirectional control characters")
		}
	}
	return nil
}

// SafeDisplay strips characters that could misrepresent a value when rendered.
//
// Applied to values that come from a remote host rather than from a form -- file
// names, process command lines, service descriptions. Those cannot be rejected,
// because the file really is called that, but they must not be able to inject an
// escape sequence into the UI or reorder their own display.
func SafeDisplay(s string) string {
	if s == "" {
		return s
	}
	needsWork := false
	for _, r := range s {
		if unicode.IsControl(r) || isBidiControl(r) || r == utf8.RuneError {
			needsWork = true
			break
		}
	}
	if !needsWork && utf8.ValidString(s) {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			b.WriteRune(0xFFFD)
		case r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r), isBidiControl(r):
			// A visible placeholder rather than deletion, so the name still looks
			// suspicious to a human instead of silently reading as something else.
			b.WriteString(fmt.Sprintf("\\x%02x", r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// RemotePath checks a path destined for a remote filesystem.
//
// Full traversal defence lives in the SFTP layer, which cleans and root-checks
// every path; this is the syntactic gate that runs first.
func RemotePath(s string) error {
	if s == "" {
		return errors.New("required")
	}
	if !strings.HasPrefix(s, "/") {
		return errors.New("must be an absolute path")
	}
	if strings.ContainsRune(s, 0) {
		return errors.New("must not contain a null byte")
	}
	if len(s) > 4096 {
		return errors.New("must be at most 4096 characters")
	}
	if !utf8.ValidString(s) {
		return errors.New("must be valid UTF-8")
	}
	return nil
}

// DiscoveryCIDR checks a network range for host discovery.
//
// Restricted to private ranges by default and to a /16 at most. Scanning a public
// range from someone else's infrastructure is at best rude and at worst illegal,
// and a /8 sweep is thousands of times more traffic than anybody intends.
func DiscoveryCIDR(s string, allowPublic bool) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, errors.New("must be a CIDR range such as 192.168.1.0/24")
	}
	prefix = prefix.Masked()

	minBits := 16
	if prefix.Addr().Is6() {
		minBits = 112 // comparable host count for IPv6
	}
	if prefix.Bits() < minBits {
		return netip.Prefix{}, fmt.Errorf("range is too large; use /%d or smaller", minBits)
	}
	if !allowPublic && !isPrivate(prefix.Addr()) {
		return netip.Prefix{}, errors.New("only private address ranges may be scanned")
	}
	return prefix, nil
}

func isPrivate(addr netip.Addr) bool {
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsUnspecified()
}

// TerminalSize checks a requested window size.
func TerminalSize(cols, rows int) error {
	if cols < 2 || cols > 1000 {
		return errors.New("columns must be between 2 and 1000")
	}
	if rows < 2 || rows > 1000 {
		return errors.New("rows must be between 2 and 1000")
	}
	return nil
}
