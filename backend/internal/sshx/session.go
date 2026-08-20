package sshx

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// PTYConfig describes the pseudo-terminal to allocate.
type PTYConfig struct {
	Term string
	Cols int
	Rows int
}

func (c PTYConfig) withDefaults() PTYConfig {
	if c.Term == "" {
		// xterm-256color rather than plain xterm: it is what xterm.js actually
		// implements, and claiming less means programs like htop and vim choose
		// a worse colour path than the browser can render.
		c.Term = "xterm-256color"
	}
	if c.Cols <= 0 {
		c.Cols = 80
	}
	if c.Rows <= 0 {
		c.Rows = 24
	}
	return c
}

// PTY is an interactive shell session on a host.
//
// Reads return the merged output stream: with a pseudo-terminal allocated the
// remote side already combines stdout and stderr, exactly as a physical terminal
// would, so separating them here would be wrong.
type PTY struct {
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader

	mu     sync.Mutex
	cols   int
	rows   int
	closed bool
}

// OpenPTY allocates a pseudo-terminal and starts the login shell.
func OpenPTY(client *ssh.Client, cfg PTYConfig) (*PTY, error) {
	cfg = cfg.withDefaults()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("sshx: open session: %w", err)
	}

	// ECHO and ISIG must be on: without them the shell does not echo typing and
	// Ctrl+C does not interrupt, which looks like a broken terminal rather than a
	// configuration choice. ICRNL maps the Enter key that xterm.js sends (CR) to
	// the newline the shell expects.
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.ICRNL:         1,
		ssh.ISIG:          1,
		ssh.ICANON:        1,
		ssh.IEXTEN:        1,
		ssh.OPOST:         1,
		ssh.ONLCR:         1,
		ssh.TTY_OP_ISPEED: 38400,
		ssh.TTY_OP_OSPEED: 38400,
	}

	if err := session.RequestPty(cfg.Term, cfg.Rows, cfg.Cols, modes); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshx: request pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshx: stdin pipe: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshx: stdout pipe: %w", err)
	}

	if err := session.Shell(); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("sshx: start shell: %w", err)
	}

	return &PTY{
		session: session,
		stdin:   stdin,
		stdout:  stdout,
		cols:    cfg.Cols,
		rows:    cfg.Rows,
	}, nil
}

// Read returns terminal output.
func (p *PTY) Read(b []byte) (int, error) { return p.stdout.Read(b) }

// Write sends keystrokes to the shell.
func (p *PTY) Write(b []byte) (int, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return 0, errors.New("sshx: session is closed")
	}
	return p.stdin.Write(b)
}

// Resize informs the remote of a new window size.
//
// Callers should debounce: dragging a split divider produces a resize event per
// frame, and flooding the channel with window-change requests achieves nothing
// the last one would not.
func (p *PTY) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return fmt.Errorf("sshx: invalid window size %dx%d", cols, rows)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errors.New("sshx: session is closed")
	}
	if p.cols == cols && p.rows == rows {
		p.mu.Unlock()
		return nil
	}
	p.cols, p.rows = cols, rows
	p.mu.Unlock()

	return p.session.WindowChange(rows, cols)
}

// Size returns the current window size, which is server-side state and therefore
// survives a browser reattaching.
func (p *PTY) Size() (cols, rows int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cols, p.rows
}

// Signal sends a signal to the remote process group.
func (p *PTY) Signal(sig ssh.Signal) error { return p.session.Signal(sig) }

// Wait blocks until the shell exits, returning the exit status.
func (p *PTY) Wait() error { return p.session.Wait() }

// Close terminates the session.
func (p *PTY) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	// Closing stdin gives the shell a chance to exit cleanly, which leaves shell
	// history written and any trap handlers run. The session close that follows
	// is the backstop.
	_ = p.stdin.Close()
	return p.session.Close()
}

// ExitCode extracts a process exit status from a Wait error.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus()
	}
	var missing *ssh.ExitMissingError
	if errors.As(err, &missing) {
		// The remote closed the channel without reporting a status. Common when a
		// host reboots mid-command.
		return -1
	}
	return -1
}
