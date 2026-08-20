// Package shellquote produces POSIX-safe shell arguments.
//
// AXT-Term never invokes a local shell -- SSH runs in-process -- but it does build
// command strings that a *remote* shell will parse, for the System, Processes, and
// Services panels. Those commands are fixed templates with a small number of
// substituted values (a unit name, a path, a PID), and every substituted value
// goes through Quote.
//
// The rule this package encodes: inside single quotes, POSIX shells treat every
// character literally, with no escape sequences at all. The only character that
// cannot appear is the single quote itself, which is handled by closing the
// quoted run, emitting an escaped quote, and reopening. That is why the output
// looks odd but is exactly safe.
package shellquote

import "strings"

// Quote returns s as a single shell word.
//
//	foo          -> 'foo'
//	it's         -> 'it'\''s'
//	$(rm -rf /)  -> '$(rm -rf /)'    (inert: no expansion inside single quotes)
//	(empty)      -> ''
func Quote(s string) string {
	if s == "" {
		return "''"
	}

	// Fast path for values made only of characters no shell treats specially.
	// Skipping the quotes keeps generated commands readable in the audit log.
	if isPlain(s) {
		return s
	}

	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			// Close, emit a backslash-escaped quote outside quotes, reopen.
			b.WriteString(`'\''`)
			continue
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('\'')
	return b.String()
}

// Join quotes each argument and joins them with spaces.
func Join(args ...string) string {
	if len(args) == 0 {
		return ""
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = Quote(a)
	}
	return strings.Join(quoted, " ")
}

// isPlain reports whether s consists only of characters that are never special to
// a POSIX shell.
//
// The set is deliberately conservative: anything not listed gets quoted. Adding a
// character here is a security decision, so the list stays short and obvious.
func isPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9':
			continue
		case c == '-', c == '_', c == '.', c == '/', c == ':', c == '=', c == '@', c == '+', c == ',':
			continue
		default:
			return false
		}
	}
	return true
}
