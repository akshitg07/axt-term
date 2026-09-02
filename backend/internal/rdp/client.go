package rdp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Handshake and connection errors.
var (
	// ErrUnavailable means guacd itself could not be reached. Distinguished from
	// a connection failure so the UI can say "the gateway is down" rather than
	// blaming the Windows host, which is the more common and more misleading
	// reading of a bare "connection failed".
	ErrUnavailable = errors.New("rdp: guacd is unreachable")

	// ErrHandshake means guacd answered but not with what the protocol requires.
	ErrHandshake = errors.New("rdp: guacd handshake failed")

	// ErrRemote means guacd reported a failure reaching or authenticating to the
	// target. This is the case that maps to a password the user should re-check.
	ErrRemote = errors.New("rdp: the remote desktop refused the connection")
)

// RemoteError carries guacd's own error instruction.
//
// guacd reports failures as `error,<message>,<status>` where status is a
// Guacamole status code. Both halves are kept: the message is what a person
// reads, the code is what the UI branches on.
type RemoteError struct {
	Message string
	Status  int
}

func (e *RemoteError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%s (status %d: %s)", ErrRemote.Error(), e.Status, statusText(e.Status))
	}
	return fmt.Sprintf("%s: %s (status %d: %s)", ErrRemote.Error(), e.Message, e.Status, statusText(e.Status))
}

func (e *RemoteError) Unwrap() error { return ErrRemote }

// statusText names the Guacamole status codes worth distinguishing.
//
// The full set is larger; these are the ones an operator actually hits, and
// naming them turns "status 519" into something actionable.
func statusText(status int) string {
	switch status {
	case 0:
		return "success"
	case 256:
		return "unsupported"
	case 512:
		return "server error"
	case 513:
		return "server busy"
	case 514:
		return "upstream timeout"
	case 515:
		return "upstream error"
	case 516:
		return "resource not found"
	case 517:
		return "resource conflict"
	case 518:
		return "resource closed"
	case 519:
		return "upstream not found"
	case 520:
		return "upstream unavailable"
	case 521:
		return "session conflict"
	case 522:
		return "session timeout"
	case 523:
		return "session closed"
	case 768:
		return "client bad request"
	case 769:
		return "authentication required or rejected"
	case 771:
		return "client forbidden"
	default:
		return "unknown"
	}
}

// Display describes the browser's viewport at connect time.
type Display struct {
	Width  int
	Height int
	DPI    int
}

func (d Display) withDefaults() Display {
	// A sane desktop rather than a degenerate one, for the case where the client
	// connected before it had laid out the pane.
	if d.Width < 640 {
		d.Width = 1024
	}
	if d.Height < 480 {
		d.Height = 768
	}
	if d.DPI <= 0 {
		d.DPI = 96
	}
	return d
}

// Client is one connection to guacd.
type Client struct {
	conn net.Conn
	r    *Reader
	w    *Writer

	// connectionID is guacd's identifier for the connection, returned by `ready`.
	// Passing it to Select on a second connection joins the same desktop, which is
	// how a reattaching browser gets a full repaint.
	connectionID string

	// version is the protocol version guacd announced in `args`.
	version string
}

// mimetypes we advertise during the handshake.
//
// These describe what guacamole-common-js can decode in the browser, because the
// backend performs the handshake on the browser's behalf. Advertising something
// the browser cannot render would produce a desktop that draws nothing.
var (
	imageMimetypes = []string{"image/jpeg", "image/png", "image/webp"}
	audioMimetypes = []string{"audio/L16;rate=44100,channels=2"}
)

// Dial opens a connection to guacd without performing a handshake.
func Dial(ctx context.Context, addr string) (*Client, error) {
	if addr == "" {
		return nil, fmt.Errorf("%w: no address is configured", ErrUnavailable)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return &Client{
		conn: conn,
		r:    NewReader(conn),
		w:    NewWriter(conn),
	}, nil
}

// ConnectionID returns guacd's identifier for this connection.
func (c *Client) ConnectionID() string { return c.connectionID }

// Version returns the protocol version guacd announced.
func (c *Client) Version() string { return c.version }

// Conn exposes the underlying connection so the relay can set deadlines.
func (c *Client) Conn() net.Conn { return c.conn }

// Read reads one instruction from guacd.
func (c *Client) Read() (Instruction, error) { return c.r.ReadInstruction() }

// Write sends one instruction to guacd.
func (c *Client) Write(opcode string, args ...string) error { return c.w.Write(opcode, args...) }

// WriteRaw sends an already-encoded instruction to guacd.
func (c *Client) WriteRaw(encoded []byte) error { return c.w.WriteRaw(encoded) }

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Handshake performs the Guacamole handshake for a new connection.
//
// The sequence is fixed by the protocol:
//
//	-> select <protocol>
//	<- args <version>,<param name>,<param name>,...
//	-> size <w> <h> <dpi> / audio ... / video ... / image ...
//	-> connect <value>,<value>,...      (positionally matched to args)
//	<- ready $<connection id>
//
// The load-bearing detail is that `connect` is *positional*: guacd names the
// parameters it wants and expects the values back in that same order, with an
// empty string for anything unset. Building the payload from the order guacd just
// told us -- rather than from an order compiled into this binary -- is what makes
// the client work across guacd versions that add or reorder parameters.
func (c *Client) Handshake(ctx context.Context, protocol string, params map[string]string, display Display) error {
	if deadline, ok := ctx.Deadline(); ok {
		// One deadline for the whole handshake. RDP with NLA can legitimately take
		// several seconds; hanging forever is what must not happen.
		if err := c.conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("%w: %w", ErrHandshake, err)
		}
		defer func() { _ = c.conn.SetDeadline(time.Time{}) }()
	}

	if err := c.w.Write("select", protocol); err != nil {
		return fmt.Errorf("%w: sending select: %w", ErrHandshake, err)
	}

	names, err := c.readArgs()
	if err != nil {
		return err
	}

	display = display.withDefaults()
	if err := c.sendClientCapabilities(display); err != nil {
		return err
	}

	// Positional mapping. Unknown-to-us parameters are sent empty, which guacd
	// treats as "use the default" -- the same thing the Guacamole web client does.
	values := make([]string, len(names))
	for i, name := range names {
		values[i] = params[name]
	}
	if err := c.w.Write("connect", values...); err != nil {
		return fmt.Errorf("%w: sending connect: %w", ErrHandshake, err)
	}

	return c.readReady()
}

// Join attaches to an existing guacd connection by its id.
//
// This is guacd's own multi-client mechanism -- the one screen sharing uses -- and
// it is how a reattaching browser gets its display back. A joining client is sent
// the current state of the display, which a stateful stream of drawing operations
// cannot otherwise reconstruct: replaying the instructions from the start would
// mean keeping every instruction ever sent, and replaying from a ring buffer would
// paint a desktop assembled from a hole in the middle of its own history.
func (c *Client) Join(ctx context.Context, connectionID string, display Display) error {
	if connectionID == "" {
		return fmt.Errorf("%w: no connection id to join", ErrHandshake)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("%w: %w", ErrHandshake, err)
		}
		defer func() { _ = c.conn.SetDeadline(time.Time{}) }()
	}

	// guacd distinguishes a join from a new connection by the leading '$'.
	target := connectionID
	if !strings.HasPrefix(target, "$") {
		target = "$" + target
	}
	if err := c.w.Write("select", target); err != nil {
		return fmt.Errorf("%w: sending select for join: %w", ErrHandshake, err)
	}

	names, err := c.readArgs()
	if err != nil {
		return err
	}

	display = display.withDefaults()
	if err := c.sendClientCapabilities(display); err != nil {
		return err
	}

	// A joining client supplies no connection parameters: the connection already
	// exists and its parameters are guacd's, not ours to restate.
	values := make([]string, len(names))
	if err := c.w.Write("connect", values...); err != nil {
		return fmt.Errorf("%w: sending connect for join: %w", ErrHandshake, err)
	}

	return c.readReady()
}

// sendClientCapabilities sends the size, audio, video, and image instructions.
func (c *Client) sendClientCapabilities(display Display) error {
	if err := c.w.Write("size",
		strconv.Itoa(display.Width),
		strconv.Itoa(display.Height),
		strconv.Itoa(display.DPI)); err != nil {
		return fmt.Errorf("%w: sending size: %w", ErrHandshake, err)
	}
	if err := c.w.Write("audio", audioMimetypes...); err != nil {
		return fmt.Errorf("%w: sending audio: %w", ErrHandshake, err)
	}
	// No video mimetypes: guacd streams video only for protocols and codecs we do
	// not offer, and advertising support we do not have invites it to send frames
	// the browser would drop.
	if err := c.w.Write("video"); err != nil {
		return fmt.Errorf("%w: sending video: %w", ErrHandshake, err)
	}
	if err := c.w.Write("image", imageMimetypes...); err != nil {
		return fmt.Errorf("%w: sending image: %w", ErrHandshake, err)
	}
	return nil
}

// readArgs reads the `args` instruction and returns the parameter names.
//
// The first element is the protocol version, not a parameter, so it is split off
// rather than being mistaken for one -- sending a value in its position would
// shift every subsequent parameter by one and produce a connection with the
// password in the domain field.
func (c *Client) readArgs() ([]string, error) {
	in, err := c.readSkippingNops()
	if err != nil {
		return nil, fmt.Errorf("%w: waiting for args: %w", ErrHandshake, err)
	}
	if in.Opcode == "error" {
		return nil, remoteErrorFrom(in)
	}
	if in.Opcode != "args" {
		return nil, fmt.Errorf("%w: expected args, got %q", ErrHandshake, in.Opcode)
	}
	if len(in.Args) == 0 {
		return nil, fmt.Errorf("%w: args carried no protocol version", ErrHandshake)
	}

	c.version = in.Args[0]
	names := in.Args[1:]
	out := make([]string, len(names))
	copy(out, names)
	return out, nil
}

// readReady reads the `ready` instruction that completes the handshake.
func (c *Client) readReady() error {
	in, err := c.readSkippingNops()
	if err != nil {
		return fmt.Errorf("%w: waiting for ready: %w", ErrHandshake, err)
	}
	switch in.Opcode {
	case "ready":
		if len(in.Args) == 0 || in.Args[0] == "" {
			return fmt.Errorf("%w: ready carried no connection id", ErrHandshake)
		}
		c.connectionID = in.Args[0]
		return nil
	case "error":
		// This is the interesting failure: guacd is fine, the target refused.
		return remoteErrorFrom(in)
	case "disconnect":
		return fmt.Errorf("%w: guacd disconnected during the handshake", ErrHandshake)
	default:
		return fmt.Errorf("%w: expected ready, got %q", ErrHandshake, in.Opcode)
	}
}

// readSkippingNops reads the next meaningful instruction.
//
// guacd may emit `nop` at any time as a keepalive, including mid-handshake, and
// treating one as a protocol violation would fail connections at random.
func (c *Client) readSkippingNops() (Instruction, error) {
	for {
		in, err := c.r.ReadInstruction()
		if err != nil {
			return Instruction{}, err
		}
		if in.Opcode == "nop" {
			continue
		}
		return in, nil
	}
}

// remoteErrorFrom converts an `error` instruction into a typed error.
func remoteErrorFrom(in Instruction) error {
	status := 0
	if len(in.Args) > 1 {
		if parsed, err := strconv.Atoi(in.Args[1]); err == nil {
			status = parsed
		}
	}
	return &RemoteError{Message: in.Arg(0), Status: status}
}
