package sshx

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultMaxOutput bounds captured output per stream.
//
// A command that produces gigabytes -- `cat` on a log file, a runaway loop --
// must not be able to exhaust backend memory, and for aggregation the first
// megabyte is what anybody reads.
const DefaultMaxOutput = 1 << 20 // 1 MiB

// ExecResult is the outcome of one non-interactive command.
type ExecResult struct {
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	Truncated bool
	Duration  time.Duration
}

// Exec runs a command without a pseudo-terminal and captures its output.
//
// No PTY, deliberately. The output here is for aggregation and parsing, not
// rendering, and a TTY makes programs page, colourise, and line-wrap -- all of
// which corrupt machine-readable output. It also means no shell job control is
// involved, so a hung command is cleanly killable by closing the channel.
func Exec(ctx context.Context, client *ssh.Client, command string, maxOutput int) (*ExecResult, error) {
	if maxOutput <= 0 {
		maxOutput = DefaultMaxOutput
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("sshx: open session: %w", err)
	}
	defer func() { _ = session.Close() }()

	stdout := &cappedBuffer{limit: maxOutput}
	stderr := &cappedBuffer{limit: maxOutput}
	session.Stdout = stdout
	session.Stderr = stderr

	start := time.Now()
	if err := session.Start(command); err != nil {
		return nil, fmt.Errorf("sshx: start command: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	select {
	case waitErr := <-done:
		result := &ExecResult{
			ExitCode:  ExitCode(waitErr),
			Stdout:    stdout.Bytes(),
			Stderr:    stderr.Bytes(),
			Truncated: stdout.Truncated() || stderr.Truncated(),
			Duration:  time.Since(start),
		}
		// A non-zero exit status is a result, not a transport error: `grep` with
		// no match exits 1 and that is information, not a failure to report.
		var exitErr *ssh.ExitError
		if waitErr != nil && !errors.As(waitErr, &exitErr) {
			var missing *ssh.ExitMissingError
			if !errors.As(waitErr, &missing) {
				return result, fmt.Errorf("sshx: command failed: %w", waitErr)
			}
		}
		return result, nil

	case <-ctx.Done():
		// Closing the session tears down the channel, which the remote sees as a
		// hangup. Partial output collected so far is still returned, because
		// knowing how far a timed-out command got is usually the whole question.
		_ = session.Signal(ssh.SIGTERM)
		_ = session.Close()
		return &ExecResult{
			ExitCode:  -1,
			Stdout:    stdout.Bytes(),
			Stderr:    stderr.Bytes(),
			Truncated: stdout.Truncated() || stderr.Truncated(),
			Duration:  time.Since(start),
		}, ctx.Err()
	}
}

// ExecCombined runs a command and returns stdout, falling back to stderr when
// stdout is empty. Convenient for the many diagnostic commands whose useful
// output could arrive on either stream.
func ExecCombined(ctx context.Context, client *ssh.Client, command string, maxOutput int) (string, error) {
	res, err := Exec(ctx, client, command, maxOutput)
	if err != nil {
		return "", err
	}
	if len(res.Stdout) == 0 && len(res.Stderr) > 0 {
		return string(res.Stderr), nil
	}
	return string(res.Stdout), nil
}

// cappedBuffer accumulates output up to a limit and records that it truncated.
//
// Writes past the limit are discarded but still reported as accepted, so the
// remote process is never blocked by a full buffer -- blocking it would change
// the behaviour of the command being observed.
type cappedBuffer struct {
	mu        sync.Mutex
	buf       []byte
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	room := b.limit - len(b.buf)
	if room <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		b.buf = append(b.buf, p[:room]...)
		b.truncated = true
		return len(p), nil
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *cappedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, len(b.buf))
	copy(out, b.buf)
	return out
}

func (b *cappedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}
