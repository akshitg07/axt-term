package terminal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/axt-term/axt-term/backend/internal/logging"
)

// Recorder writes an asciicast v2 file.
//
// The format is one JSON header line followed by one JSON array per event:
// [elapsedSeconds, streamCode, data]. It is the de facto standard for terminal
// recordings, so a recording downloaded from AXT-Term plays in asciinema and
// other existing tooling rather than needing a bespoke player.
//
// # On redaction
//
// Output is passed through the same scrubber the logger uses, which removes
// PEM private key blocks, bearer tokens, and "password=" style assignments. This
// is best-effort and cannot be otherwise: a pattern split across two reads from
// the pseudo-terminal will not match, and no filter can recognise an arbitrary
// secret in arbitrary output.
//
// A session recording is therefore sensitive material. Files are created 0600,
// live in a directory only the service user can read, and the terminal shows a
// recording indicator the whole time one is being written.
type Recorder struct {
	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
	start  time.Time
	path   string
	closed bool
}

type asciicastHeader struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Title     string            `json:"title,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// NewRecorder creates a recording file.
func NewRecorder(path string, cols, rows int, title string) (*Recorder, error) {
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("terminal: create recording directory: %w", err)
	}
	// O_EXCL so a recording never silently overwrites another.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("terminal: create recording %s: %w", path, err)
	}

	now := time.Now()
	r := &Recorder{
		file:   file,
		writer: bufio.NewWriterSize(file, 32*1024),
		start:  now,
		path:   path,
	}

	header := asciicastHeader{
		Version:   2,
		Width:     cols,
		Height:    rows,
		Timestamp: now.Unix(),
		Title:     title,
		Env:       map[string]string{"TERM": "xterm-256color"},
	}
	encoded, err := json.Marshal(header)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("terminal: encode recording header: %w", err)
	}
	if _, err := r.writer.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("terminal: write recording header: %w", err)
	}
	return r, nil
}

// Path returns the file being written.
func (r *Recorder) Path() string { return r.path }

// WriteOutput records host output.
func (r *Recorder) WriteOutput(data []byte) { r.writeEvent("o", logging.ScrubString(string(data))) }

// WriteInput records user keystrokes.
//
// Recorded so a playback shows what was typed, not only what appeared. Note that
// this is also the stream most likely to contain a typed password, which is why
// input recording only happens in full mode and full mode is opt-in per host.
func (r *Recorder) WriteInput(data []byte) { r.writeEvent("i", logging.ScrubString(string(data))) }

// WriteResize records a window size change so playback reflows correctly.
func (r *Recorder) WriteResize(cols, rows int) {
	r.writeEvent("r", fmt.Sprintf("%dx%d", cols, rows))
}

func (r *Recorder) writeEvent(stream, data string) {
	if data == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}

	event := []any{time.Since(r.start).Seconds(), stream, data}
	encoded, err := json.Marshal(event)
	if err != nil {
		return
	}
	// A failed write must not break the session: recording is a side effect, and
	// losing it is preferable to interrupting someone's shell.
	_, _ = r.writer.Write(append(encoded, '\n'))
}

// Close flushes and closes the file.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true

	var firstErr error
	if err := r.writer.Flush(); err != nil {
		firstErr = err
	}
	if err := r.file.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Duration reports how long the recording has been running.
func (r *Recorder) Duration() time.Duration { return time.Since(r.start) }
