// Package events is the in-process publish/subscribe bus behind /ws/events.
//
// In-process is correct here rather than a compromise: every WebSocket client is
// connected to this process, and every live PTY is pinned to it, so a broker would
// add a component and a failure mode without adding a capability (ADR 0005).
package events

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"
)

// Event kinds.
const (
	KindTransferProgress = "transfer.progress"
	KindTransferDone     = "transfer.done"
	KindHostHealth       = "host.health"
	KindSessionState     = "session.state"
	KindExecProgress     = "exec.progress"
	KindExecDone         = "exec.done"
	KindTunnelState      = "tunnel.state"
	KindNotification     = "notification"
	KindHostKeyPending   = "hostkey.pending"
	KindServerShutdown   = "server.shutdown"
)

// Notification levels.
const (
	LevelInfo    = "info"
	LevelSuccess = "success"
	LevelWarning = "warning"
	LevelError   = "error"
)

// Event is one message delivered to subscribers.
//
// UserID scopes delivery. An empty UserID broadcasts to everyone, which is used
// only for instance-wide notices such as an imminent shutdown.
type Event struct {
	Kind   string         `json:"t"`
	UserID string         `json:"-"`
	At     time.Time      `json:"at"`
	Data   map[string]any `json:"-"`
}

// MarshalJSON flattens Data into the top-level object, so a client switches on
// "t" and reads siblings directly rather than unwrapping a nested payload.
func (e Event) MarshalJSON() ([]byte, error) {
	out := make(map[string]any, len(e.Data)+2)
	for k, v := range e.Data {
		out[k] = v
	}
	out["t"] = e.Kind
	if !e.At.IsZero() {
		out["at"] = e.At.UTC().Format(time.RFC3339Nano)
	}
	return json.Marshal(out)
}

// subscriberBuffer bounds how far behind a client may fall.
//
// A browser that stops reading -- a backgrounded tab on a throttled timer, a
// suspended laptop -- must not grow the publisher's memory. Sixty-four events is
// several seconds of transfer progress, and a client that misses more than that
// will refresh its state on reconnect anyway.
const subscriberBuffer = 64

// Subscription is one client's event stream.
type Subscription struct {
	ID     int64
	UserID string
	C      <-chan Event

	bus  *Bus
	send chan Event
}

// Close unsubscribes. Safe to call more than once.
func (s *Subscription) Close() {
	if s == nil || s.bus == nil {
		return
	}
	s.bus.unsubscribe(s.ID)
}

// Bus fans events out to subscribers.
type Bus struct {
	log *slog.Logger

	mu     sync.RWMutex
	next   int64
	subs   map[int64]*Subscription
	closed bool

	// dropped counts events discarded because a subscriber was too slow, exposed
	// as a metric so a persistently slow client is visible rather than silent.
	dropped uint64
}

// NewBus creates a bus.
func NewBus(log *slog.Logger) *Bus {
	return &Bus{log: log, subs: make(map[int64]*Subscription)}
}

// Subscribe registers a client. userID scopes which events it receives.
func (b *Bus) Subscribe(userID string) *Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.next++
	send := make(chan Event, subscriberBuffer)
	sub := &Subscription{
		ID:     b.next,
		UserID: userID,
		C:      send,
		bus:    b,
		send:   send,
	}
	if b.closed {
		close(send)
		return sub
	}
	b.subs[sub.ID] = sub
	return sub
}

func (b *Bus) unsubscribe(id int64) {
	b.mu.Lock()
	sub, ok := b.subs[id]
	if ok {
		delete(b.subs, id)
	}
	b.mu.Unlock()
	if ok {
		close(sub.send)
	}
}

// Publish delivers an event to matching subscribers.
//
// Never blocks: a full subscriber channel drops the event for that subscriber
// only. Blocking here would let one stalled browser tab stall a file transfer.
func (b *Bus) Publish(e Event) {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return
	}

	for _, sub := range b.subs {
		if e.UserID != "" && sub.UserID != e.UserID {
			continue
		}
		select {
		case sub.send <- e:
		default:
			b.dropped++
		}
	}
}

// Helpers for the events published from more than one place.

// PublishNotification sends a user-facing message.
func (b *Bus) PublishNotification(userID, level, title, message string) {
	b.Publish(Event{
		Kind:   KindNotification,
		UserID: userID,
		Data: map[string]any{
			"level":   level,
			"title":   title,
			"message": message,
		},
	})
}

// PublishSessionState reports a session lifecycle change.
func (b *Bus) PublishSessionState(userID, sessionID, state, reason string) {
	b.Publish(Event{
		Kind:   KindSessionState,
		UserID: userID,
		Data: map[string]any{
			"session_id": sessionID,
			"state":      state,
			"reason":     reason,
		},
	})
}

// PublishHostHealth reports a health check result.
func (b *Bus) PublishHostHealth(hostID, status string, latencyMS *int) {
	data := map[string]any{"host_id": hostID, "status": status}
	if latencyMS != nil {
		data["latency_ms"] = *latencyMS
	}
	// Health is instance-wide state, not per-user, so it broadcasts.
	b.Publish(Event{Kind: KindHostHealth, Data: data})
}

// Stats reports subscriber count and dropped events, for /metrics.
func (b *Bus) Stats() (subscribers int, dropped uint64) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs), b.dropped
}

// Close shuts the bus down, closing every subscriber channel.
func (b *Bus) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	subs := make([]*Subscription, 0, len(b.subs))
	for _, s := range b.subs {
		subs = append(subs, s)
	}
	b.subs = make(map[int64]*Subscription)
	b.mu.Unlock()

	for _, s := range subs {
		close(s.send)
	}
}
