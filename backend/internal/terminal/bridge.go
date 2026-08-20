package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/axt-term/axt-term/backend/internal/auth"
	"github.com/axt-term/axt-term/backend/internal/events"
	"github.com/axt-term/axt-term/backend/internal/httpx"
	"github.com/axt-term/axt-term/backend/internal/validate"
	"github.com/coder/websocket"
)

// WebSocket tuning.
const (
	// readLimit allows a large paste but nothing pathological.
	readLimit = 1 << 20

	// pingInterval and pongTimeout detect half-open connections. TCP will not
	// report a laptop that closed its lid for minutes; an application-level ping
	// turns that into a two-second "Reconnecting…" instead of a terminal that
	// appears to work but is dead.
	pingInterval = 30 * time.Second
	pongTimeout  = 10 * time.Second

	// writeTimeout bounds a single frame write, so one wedged client cannot hold
	// a goroutine forever.
	writeTimeout = 15 * time.Second
)

// Bridge serves the WebSocket endpoints.
type Bridge struct {
	registry       *Registry
	tickets        *auth.TicketStore
	bus            *events.Bus
	log            *slog.Logger
	allowedOrigins []string
}

// NewBridge creates the WebSocket bridge.
func NewBridge(registry *Registry, tickets *auth.TicketStore, bus *events.Bus, allowedOrigins []string, log *slog.Logger) *Bridge {
	return &Bridge{
		registry:       registry,
		tickets:        tickets,
		bus:            bus,
		log:            log,
		allowedOrigins: allowedOrigins,
	}
}

// acceptOptions builds the upgrade options.
//
// OriginPatterns is set explicitly rather than relying on the library default,
// and compression is disabled: terminal output is mostly short bursts where
// per-message deflate costs more CPU than it saves bandwidth, and it has a
// history of subtle interoperability problems.
func (b *Bridge) acceptOptions() *websocket.AcceptOptions {
	patterns := make([]string, 0, len(b.allowedOrigins))
	for _, origin := range b.allowedOrigins {
		// coder/websocket matches host patterns, not full URLs.
		if host := hostOf(origin); host != "" {
			patterns = append(patterns, host)
		}
	}
	return &websocket.AcceptOptions{
		OriginPatterns:  patterns,
		CompressionMode: websocket.CompressionDisabled,
	}
}

// hostOf reduces an origin to the host pattern coder/websocket matches against.
func hostOf(origin string) string {
	if idx := strings.Index(origin, "://"); idx >= 0 {
		return origin[idx+3:]
	}
	return origin
}

// ServeTerminal upgrades to a WebSocket and attaches to a session.
//
// Authentication is the single-use ticket, consumed before the upgrade so an
// invalid one produces a clean HTTP error rather than a WebSocket that closes
// immediately for no visible reason.
func (b *Bridge) ServeTerminal(w http.ResponseWriter, r *http.Request) {
	ticketValue := r.URL.Query().Get("ticket")
	if ticketValue == "" {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeUnauthenticated,
			"a session ticket is required")
		return
	}

	ticket, err := b.tickets.Consume(ticketValue, httpx.ClientIP(r.Context()), "terminal")
	if err != nil {
		b.log.WarnContext(r.Context(), "rejected terminal websocket",
			slog.Any("error", err),
			slog.String("client_ip", httpx.ClientIP(r.Context())))
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeUnauthenticated,
			"this ticket is not valid; request a new one")
		return
	}

	session, err := b.registry.GetForUser(ticket.UserID, ticket.SessionID)
	if err != nil {
		httpx.NotFound(w, r, "session")
		return
	}

	fromSeq := uint64(0)
	if raw := r.URL.Query().Get("seq"); raw != "" {
		if parsed, perr := strconv.ParseUint(raw, 10, 64); perr == nil {
			fromSeq = parsed
		}
	}

	conn, err := websocket.Accept(w, r, b.acceptOptions())
	if err != nil {
		// Accept has already written a response.
		b.log.WarnContext(r.Context(), "websocket upgrade failed", slog.Any("error", err))
		return
	}
	conn.SetReadLimit(readLimit)

	b.runTerminal(r, conn, session, fromSeq)
}

func (b *Bridge) runTerminal(r *http.Request, conn *websocket.Conn, session *Session, fromSeq uint64) {
	// Deliberately not r.Context(): that is cancelled when the handler returns,
	// and this connection outlives the handler's request scope conceptually even
	// though it is served from it. Cancellation is driven by the read loop, the
	// session ending, or the ping loop failing.
	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	defer cancel()

	attachment, err := session.Attach(fromSeq)
	if err != nil {
		b.closeWithError(ctx, conn, "session_unavailable", err.Error())
		return
	}
	defer attachment.Detach()

	outgoing := make(chan []byte, 64)

	// Single writer. coder/websocket permits one concurrent writer, so every
	// frame -- output, control, pong -- funnels through this goroutine.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for payload := range outgoing {
			writeCtx, writeCancel := context.WithTimeout(ctx, writeTimeout)
			err := conn.Write(writeCtx, websocket.MessageBinary, payload)
			writeCancel()
			if err != nil {
				cancel()
				return
			}
		}
	}()

	sendControl := func(c Control) {
		encoded, err := c.encode()
		if err != nil {
			return
		}
		writeCtx, writeCancel := context.WithTimeout(ctx, writeTimeout)
		defer writeCancel()
		if err := conn.Write(writeCtx, websocket.MessageText, encoded); err != nil {
			cancel()
		}
	}

	cols, rows := session.Size()
	sendControl(Control{
		Type:      CtlStatus,
		State:     string(session.State()),
		Seq:       attachment.Seq,
		Reset:     attachment.Gap,
		Host:      session.HostLabel,
		Cols:      cols,
		Rows:      rows,
		Recording: session.IsRecording(),
	})

	if len(attachment.Replay) > 0 {
		select {
		case outgoing <- frame(OpReplay, attachment.Replay):
		case <-ctx.Done():
		}
	}

	// Forward live output.
	go func() {
		for {
			select {
			case chunk, ok := <-attachment.Data:
				if !ok {
					cancel()
					return
				}
				select {
				case outgoing <- frame(OpOutput, chunk):
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Detect a session that ends while attached.
	go func() {
		select {
		case <-session.Done():
			exitCode := 0
			sendControl(Control{
				Type:     CtlExit,
				ExitCode: &exitCode,
				Reason:   session.ExitReason(),
				State:    string(session.State()),
			})
			cancel()
		case <-ctx.Done():
		}
	}()

	// Ping loop.
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pingCtx, pingCancel := context.WithTimeout(ctx, pongTimeout)
				err := conn.Ping(pingCtx)
				pingCancel()
				if err != nil {
					b.log.Debug("terminal websocket ping failed",
						slog.String("session_id", session.ID), slog.Any("error", err))
					cancel()
					return
				}
			}
		}
	}()

	// Read loop, on this goroutine so the handler returns when the client goes.
	readErr := b.readLoop(ctx, conn, session, sendControl)

	cancel()
	close(outgoing)
	<-writerDone

	status := websocket.StatusNormalClosure
	reason := "closed"
	if readErr != nil && !errors.Is(readErr, context.Canceled) {
		if websocket.CloseStatus(readErr) == -1 {
			status = websocket.StatusInternalError
			reason = "read error"
		}
	}
	_ = conn.Close(status, reason)
}

func (b *Bridge) readLoop(ctx context.Context, conn *websocket.Conn, session *Session, sendControl func(Control)) error {
	for {
		msgType, payload, err := conn.Read(ctx)
		if err != nil {
			return err
		}

		switch msgType {
		case websocket.MessageBinary:
			if len(payload) == 0 {
				continue
			}
			switch payload[0] {
			case OpInput:
				if _, err := session.Write(payload[1:]); err != nil {
					sendControl(Control{
						Type:    CtlError,
						Code:    "write_failed",
						Message: err.Error(),
					})
				}
			default:
				sendControl(Control{
					Type:    CtlError,
					Code:    "unknown_opcode",
					Message: "unrecognised binary opcode",
				})
			}

		case websocket.MessageText:
			var c Control
			if err := json.Unmarshal(payload, &c); err != nil {
				sendControl(Control{Type: CtlError, Code: "bad_control", Message: "malformed control frame"})
				continue
			}
			b.handleControl(session, c, sendControl)
		}
	}
}

func (b *Bridge) handleControl(session *Session, c Control, sendControl func(Control)) {
	switch c.Type {
	case CtlResize:
		if err := validate.TerminalSize(c.Cols, c.Rows); err != nil {
			sendControl(Control{Type: CtlError, Code: "bad_size", Message: err.Error()})
			return
		}
		if err := session.Resize(c.Cols, c.Rows); err != nil {
			sendControl(Control{Type: CtlError, Code: "resize_failed", Message: err.Error()})
			return
		}
		sendControl(Control{Type: CtlAck, Cols: c.Cols, Rows: c.Rows})

	case CtlPing:
		sendControl(Control{Type: CtlPong})

	case CtlPong:
		// Nothing to do; the library handles protocol-level pongs.

	default:
		sendControl(Control{
			Type:    CtlError,
			Code:    "unknown_control",
			Message: "unrecognised control message " + c.Type,
		})
	}
}

func (b *Bridge) closeWithError(ctx context.Context, conn *websocket.Conn, code, message string) {
	encoded, err := Control{Type: CtlError, Code: code, Message: message}.encode()
	if err == nil {
		writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
		_ = conn.Write(writeCtx, websocket.MessageText, encoded)
		cancel()
	}
	_ = conn.Close(websocket.StatusPolicyViolation, code)
}

// ServeEvents streams a user's notification feed.
//
// One socket per browser tab-group carries transfer progress, health changes, job
// results, and notifications. Terminal I/O stays on its own socket so a burst of
// events cannot delay keystroke echo.
func (b *Bridge) ServeEvents(w http.ResponseWriter, r *http.Request) {
	ticketValue := r.URL.Query().Get("ticket")
	if ticketValue == "" {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeUnauthenticated,
			"a ticket is required")
		return
	}
	ticket, err := b.tickets.Consume(ticketValue, httpx.ClientIP(r.Context()), "events")
	if err != nil {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeUnauthenticated,
			"this ticket is not valid; request a new one")
		return
	}

	conn, err := websocket.Accept(w, r, b.acceptOptions())
	if err != nil {
		return
	}
	conn.SetReadLimit(4096)

	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	defer cancel()

	sub := b.bus.Subscribe(ticket.UserID)
	defer sub.Close()

	// Drain client frames so the connection's read side stays healthy and a
	// close is noticed promptly. The events socket is one-directional otherwise.
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				cancel()
				return
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pingCtx, pingCancel := context.WithTimeout(ctx, pongTimeout)
				err := conn.Ping(pingCtx)
				pingCancel()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			_ = conn.Close(websocket.StatusNormalClosure, "closed")
			return
		case event, ok := <-sub.C:
			if !ok {
				_ = conn.Close(websocket.StatusGoingAway, "server shutting down")
				return
			}
			encoded, err := json.Marshal(event)
			if err != nil {
				continue
			}
			writeCtx, writeCancel := context.WithTimeout(ctx, writeTimeout)
			err = conn.Write(writeCtx, websocket.MessageText, encoded)
			writeCancel()
			if err != nil {
				cancel()
				_ = conn.Close(websocket.StatusInternalError, "write failed")
				return
			}
		}
	}
}
