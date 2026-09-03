package rdp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeGuacd is the server half of a guacd conversation, driven from a test.
type fakeGuacd struct {
	t    *testing.T
	conn net.Conn
	r    *Reader
	w    *Writer

	// received records every instruction the client sent, in order.
	received []Instruction
}

func newFakeGuacd(t *testing.T) (*Client, *fakeGuacd) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	client := &Client{
		conn: clientConn,
		r:    NewReader(clientConn),
		w:    NewWriter(clientConn),
	}
	return client, &fakeGuacd{
		t:    t,
		conn: serverConn,
		r:    NewReader(serverConn),
		w:    NewWriter(serverConn),
	}
}

func (f *fakeGuacd) read() Instruction {
	f.t.Helper()
	in, err := f.r.ReadInstruction()
	if err != nil {
		f.t.Fatalf("fake guacd could not read: %v", err)
	}
	f.received = append(f.received, in)
	return in
}

func (f *fakeGuacd) write(opcode string, args ...string) {
	f.t.Helper()
	if err := f.w.Write(opcode, args...); err != nil {
		f.t.Fatalf("fake guacd could not write %s: %v", opcode, err)
	}
}

// sent returns the instruction with the given opcode that the client sent.
func (f *fakeGuacd) sent(opcode string) (Instruction, bool) {
	for _, in := range f.received {
		if in.Opcode == opcode {
			return in, true
		}
	}
	return Instruction{}, false
}

// TestHandshakeMapsConnectPositionally is the load-bearing handshake test.
//
// guacd names the parameters it wants and expects the values back in that order.
// The parameter names here are deliberately shuffled relative to any order this
// package might have compiled in, and one of them ("colour-preference") is a name
// we know nothing about -- it must come back empty rather than shifting everything
// after it. Getting this wrong connects with the password in the domain field.
func TestHandshakeMapsConnectPositionally(t *testing.T) {
	client, guacd := newFakeGuacd(t)

	names := []string{"port", "colour-preference", "password", "hostname", "domain", "username"}

	done := make(chan error, 1)
	go func() {
		params := Params{
			"hostname": "10.0.4.11",
			"port":     "3389",
			"username": "administrator",
			"password": "hunter2",
			"domain":   "CORP",
			// A parameter guacd did not ask for must simply not be sent.
			"unrequested": "ignored",
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- client.Handshake(ctx, "rdp", params, Display{Width: 1280, Height: 800, DPI: 96})
	}()

	if in := guacd.read(); in.Opcode != "select" || in.Arg(0) != "rdp" {
		t.Fatalf("expected select rdp, got %#v", in)
	}
	guacd.write("args", append([]string{"VERSION_1_5_0"}, names...)...)

	guacd.read() // size
	guacd.read() // audio
	guacd.read() // video
	guacd.read() // image
	connect := guacd.read()

	guacd.write("ready", "$c9f3e1a0-0001")

	if err := <-done; err != nil {
		t.Fatalf("Handshake returned %v", err)
	}

	if connect.Opcode != "connect" {
		t.Fatalf("expected connect, got %q", connect.Opcode)
	}
	// The leading element answers guacd's version announcement; the parameter
	// values follow in the order guacd named them. guacd counts the version slot,
	// so a payload without it is one element short of what guacd expects.
	want := []string{"VERSION_1_5_0", "3389", "", "hunter2", "10.0.4.11", "CORP", "administrator"}
	if len(connect.Args) != len(want) {
		t.Fatalf("connect carried %d values, want %d: %#v", len(connect.Args), len(want), connect.Args)
	}
	for i := range want {
		if connect.Args[i] != want[i] {
			t.Errorf("connect value %d = %q, want %q", i, connect.Args[i], want[i])
		}
	}

	if client.ConnectionID() != "$c9f3e1a0-0001" {
		t.Errorf("ConnectionID() = %q", client.ConnectionID())
	}
	if client.Version() != "VERSION_1_5_0" {
		t.Errorf("Version() = %q", client.Version())
	}

	// The display the browser asked for must reach guacd, not a default.
	size, ok := guacd.sent("size")
	if !ok {
		t.Fatal("no size instruction was sent")
	}
	if size.Arg(0) != "1280" || size.Arg(1) != "800" || size.Arg(2) != "96" {
		t.Errorf("size = %#v, want 1280x800@96", size.Args)
	}
}

func TestHandshakeSubstitutesUnusableDisplay(t *testing.T) {
	client, guacd := newFakeGuacd(t)

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// A client that connects before it has laid out its pane sends zeroes.
		done <- client.Handshake(ctx, "rdp", Params{}, Display{})
	}()

	guacd.read()
	guacd.write("args", "VERSION_1_5_0")
	size := guacd.read()
	guacd.read()
	guacd.read()
	guacd.read()
	guacd.read()
	guacd.write("ready", "$id")
	if err := <-done; err != nil {
		t.Fatalf("Handshake returned %v", err)
	}

	if size.Arg(0) == "0" || size.Arg(1) == "0" {
		t.Errorf("a zero display reached guacd: %#v", size.Args)
	}
}

func TestHandshakeReportsRemoteError(t *testing.T) {
	client, guacd := newFakeGuacd(t)

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- client.Handshake(ctx, "rdp", Params{}, Display{Width: 1024, Height: 768})
	}()

	guacd.read()
	guacd.write("args", "VERSION_1_5_0", "hostname")
	for i := 0; i < 5; i++ {
		guacd.read()
	}
	// 769 is the status a rejected password produces.
	guacd.write("error", "Authentication failure", "769")

	err := <-done
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrRemote) {
		t.Errorf("error should wrap ErrRemote, got %v", err)
	}

	var remote *RemoteError
	if !errors.As(err, &remote) {
		t.Fatalf("error should be a *RemoteError, got %T", err)
	}
	if remote.Status != 769 {
		t.Errorf("Status = %d, want 769", remote.Status)
	}
	// The message must name the cause; "connection failed" would send somebody
	// looking at the network instead of the credential.
	if !strings.Contains(err.Error(), "Authentication failure") {
		t.Errorf("error text lost guacd's message: %v", err)
	}
	if !strings.Contains(err.Error(), "authentication") {
		t.Errorf("error text should explain status 769: %v", err)
	}
}

func TestHandshakeSkipsNops(t *testing.T) {
	// guacd may emit nop as a keepalive at any point, mid-handshake included.
	// Treating one as a protocol violation would fail connections at random.
	client, guacd := newFakeGuacd(t)

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- client.Handshake(ctx, "rdp", Params{"hostname": "h"}, Display{Width: 1024, Height: 768})
	}()

	guacd.read()
	guacd.write("nop")
	guacd.write("args", "VERSION_1_5_0", "hostname")
	for i := 0; i < 5; i++ {
		guacd.read()
	}
	guacd.write("nop")
	guacd.write("ready", "$id")

	if err := <-done; err != nil {
		t.Fatalf("Handshake returned %v", err)
	}
}

func TestHandshakeRejectsUnexpectedOpcode(t *testing.T) {
	client, guacd := newFakeGuacd(t)

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- client.Handshake(ctx, "rdp", Params{}, Display{Width: 1024, Height: 768})
	}()

	guacd.read()
	guacd.write("mouse", "1", "1")

	err := <-done
	if !errors.Is(err, ErrHandshake) {
		t.Errorf("expected ErrHandshake, got %v", err)
	}
}

// TestJoinSelectsTheExistingConnection covers the reattach path: a returning
// viewer needs a full repaint, which guacd produces for a client that joins an
// existing connection by id.
func TestJoinSelectsTheExistingConnection(t *testing.T) {
	client, guacd := newFakeGuacd(t)

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Deliberately without the '$' prefix, which Join must add.
		done <- client.Join(ctx, "c9f3e1a0-0001", Display{Width: 1024, Height: 768})
	}()

	sel := guacd.read()
	if sel.Opcode != "select" {
		t.Fatalf("expected select, got %q", sel.Opcode)
	}
	if sel.Arg(0) != "$c9f3e1a0-0001" {
		t.Errorf("select argument = %q, want the id prefixed with $", sel.Arg(0))
	}

	guacd.write("args", "VERSION_1_5_0", "hostname", "password")
	for i := 0; i < 4; i++ {
		guacd.read()
	}
	connect := guacd.read()
	guacd.write("ready", "$c9f3e1a0-0001")

	if err := <-done; err != nil {
		t.Fatalf("Join returned %v", err)
	}

	// A joining client restates no parameters: the connection already exists and
	// its parameters are guacd's, not ours to resend. The version slot is still
	// answered, because guacd counts every element it asked for.
	if len(connect.Args) != 3 {
		t.Fatalf("join connect carried %d values, want 3: %#v", len(connect.Args), connect.Args)
	}
	if connect.Arg(0) != "VERSION_1_5_0" {
		t.Errorf("join connect value 0 = %q, want the negotiated version", connect.Arg(0))
	}
	for i, value := range connect.Args[1:] {
		if value != "" {
			t.Errorf("join connect value %d = %q, want empty", i+1, value)
		}
	}
}

// TestHandshakeAnswersTheVersionAnnouncement covers the arity rule that guacd
// reports as "Client did not return the expected number of arguments" -- and
// reports only *after* sending `ready`, so the handshake looks like it worked and
// the desktop dies a moment later.
func TestHandshakeAnswersTheVersionAnnouncement(t *testing.T) {
	client, guacd := newFakeGuacd(t)

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- client.Handshake(ctx, "rdp", Params{"hostname": "h"}, Display{Width: 1024, Height: 768})
	}()

	guacd.read()
	guacd.write("args", "VERSION_1_5_0", "hostname", "port")
	for i := 0; i < 4; i++ {
		guacd.read()
	}
	connect := guacd.read()
	guacd.write("ready", "$id")
	if err := <-done; err != nil {
		t.Fatalf("Handshake returned %v", err)
	}

	// Three elements for three announced: the version plus two parameters.
	if len(connect.Args) != 3 {
		t.Fatalf("connect carried %d values, want 3: %#v", len(connect.Args), connect.Args)
	}
	if connect.Arg(0) != "VERSION_1_5_0" {
		t.Errorf("connect value 0 = %q, want the negotiated version", connect.Arg(0))
	}
	if connect.Arg(1) != "h" {
		t.Errorf("connect value 1 = %q, want the hostname", connect.Arg(1))
	}
}

// TestHandshakeNegotiatesDownToGuacdsVersion covers a daemon older than this
// client: answering with our own newer version would claim support for
// instructions guacd will not send and we have not implemented against.
func TestHandshakeNegotiatesDownToGuacdsVersion(t *testing.T) {
	client, guacd := newFakeGuacd(t)

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- client.Handshake(ctx, "rdp", Params{"hostname": "h"}, Display{Width: 1024, Height: 768})
	}()

	guacd.read()
	guacd.write("args", "VERSION_1_1_0", "hostname")
	for i := 0; i < 4; i++ {
		guacd.read()
	}
	connect := guacd.read()
	guacd.write("ready", "$id")
	if err := <-done; err != nil {
		t.Fatalf("Handshake returned %v", err)
	}

	if connect.Arg(0) != "VERSION_1_1_0" {
		t.Errorf("connect value 0 = %q, want guacd's older version", connect.Arg(0))
	}
	if client.Version() != "VERSION_1_1_0" {
		t.Errorf("Version() = %q", client.Version())
	}
}

// TestHandshakeTreatsAMissingVersionAsAParameter covers guacd 1.0.0, which
// predates version negotiation and names a parameter in the position later
// daemons use for the version. Consuming that element as a version would shift
// every parameter by one -- the failure mode that puts the password in the domain
// field -- and would send one value too few besides.
func TestHandshakeTreatsAMissingVersionAsAParameter(t *testing.T) {
	client, guacd := newFakeGuacd(t)

	done := make(chan error, 1)
	go func() {
		params := Params{"hostname": "10.0.4.11", "password": "hunter2"}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- client.Handshake(ctx, "rdp", params, Display{Width: 1024, Height: 768})
	}()

	guacd.read()
	// No version element: the first name is a real parameter.
	guacd.write("args", "hostname", "password")
	for i := 0; i < 4; i++ {
		guacd.read()
	}
	connect := guacd.read()
	guacd.write("ready", "$id")
	if err := <-done; err != nil {
		t.Fatalf("Handshake returned %v", err)
	}

	want := []string{"10.0.4.11", "hunter2"}
	if len(connect.Args) != len(want) {
		t.Fatalf("connect carried %d values, want %d: %#v", len(connect.Args), len(want), connect.Args)
	}
	for i := range want {
		if connect.Args[i] != want[i] {
			t.Errorf("connect value %d = %q, want %q", i, connect.Args[i], want[i])
		}
	}
	if client.Version() != protocolVersion100 {
		t.Errorf("Version() = %q, want %s", client.Version(), protocolVersion100)
	}
}

func TestJoinRequiresAConnectionID(t *testing.T) {
	client, _ := newFakeGuacd(t)
	err := client.Join(context.Background(), "", Display{Width: 1024, Height: 768})
	if !errors.Is(err, ErrHandshake) {
		t.Errorf("expected ErrHandshake, got %v", err)
	}
}

func TestDialReportsUnavailableGateway(t *testing.T) {
	t.Run("no address configured", func(t *testing.T) {
		_, err := Dial(context.Background(), "")
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("expected ErrUnavailable, got %v", err)
		}
	})

	t.Run("nothing listening", func(t *testing.T) {
		// Bind and close, so the port is almost certainly free.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("could not reserve a port: %v", err)
		}
		addr := listener.Addr().String()
		_ = listener.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := Dial(ctx, addr); !errors.Is(err, ErrUnavailable) {
			t.Errorf("expected ErrUnavailable, got %v", err)
		}
	})
}

// TestParamsNeverFormatSecrets is the structural half of "credentials stay on the
// backend->guacd hop". A comment asking future readers not to log the parameter
// map would not survive somebody adding a debug line; a redacting Stringer and
// LogValuer mean no formatting verb reveals a value.
func TestParamsNeverFormatSecrets(t *testing.T) {
	params := Params{
		"hostname": "10.0.4.11",
		"username": "administrator",
		"password": "hunter2",
	}

	for _, rendered := range []string{
		params.String(),
		// %v on a bare map would print every value; the Stringer intercepts it.
		fmt.Sprintf("%v", params),
		fmt.Sprintf("%s", params),
		fmt.Sprintf("%+v", params),
	} {
		if strings.Contains(rendered, "hunter2") {
			t.Errorf("formatting leaked the password: %q", rendered)
		}
	}

	// And through slog, which is how this application actually logs.
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("connecting", slog.Any("params", params))

	if strings.Contains(buf.String(), "hunter2") {
		t.Errorf("slog leaked the password: %s", buf.String())
	}
	// Key names are safe and are what makes a handshake diagnosable.
	if !strings.Contains(buf.String(), "password") {
		t.Errorf("expected the key names to be logged: %s", buf.String())
	}
}
