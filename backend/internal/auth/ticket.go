package auth

import (
	"errors"
	"sync"
	"time"
)

// WebSocket authentication uses single-use tickets rather than cookies.
//
// Browsers cannot set headers on a WebSocket handshake, and cookies *are* sent on
// cross-origin upgrades with no preflight to stop them -- that combination is
// cross-site WebSocket hijacking, and it is why cookie-only WebSocket auth is the
// standard weak point in applications like this one.
//
// A ticket is obtained over an authenticated, CSRF-checked, origin-checked HTTP
// request, lives for 30 seconds, works exactly once, and is bound to the user,
// the session, and the client address. A leaked WebSocket URL is worthless
// immediately if already used and worthless in half a minute regardless.
//
// Tickets are in-process by nature: they authorise attachment to a live PTY,
// which is pinned to this process anyway (ADR 0004), so durability would add
// nothing.

// DefaultTicketTTL is how long an issued ticket remains valid.
const DefaultTicketTTL = 30 * time.Second

// Ticket errors.
var (
	ErrTicketUnknown  = errors.New("auth: ticket is unknown or already used")
	ErrTicketExpired  = errors.New("auth: ticket has expired")
	ErrTicketMismatch = errors.New("auth: ticket does not match this client")
)

// Ticket authorises one WebSocket attachment.
type Ticket struct {
	Value     string
	UserID    string
	SessionID string
	ClientIP  string
	Purpose   string // terminal, rdp, events
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// TicketStore holds unconsumed tickets.
type TicketStore struct {
	mu      sync.Mutex
	tickets map[string]Ticket
	ttl     time.Duration
	now     func() time.Time
}

// NewTicketStore creates a store. A zero ttl uses DefaultTicketTTL.
func NewTicketStore(ttl time.Duration, now func() time.Time) *TicketStore {
	if ttl <= 0 {
		ttl = DefaultTicketTTL
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &TicketStore{tickets: make(map[string]Ticket), ttl: ttl, now: now}
}

// Issue creates a ticket for one attachment.
func (s *TicketStore) Issue(userID, sessionID, clientIP, purpose string) (Ticket, error) {
	value, _, err := NewToken()
	if err != nil {
		return Ticket{}, err
	}
	now := s.now()
	t := Ticket{
		Value:     value,
		UserID:    userID,
		SessionID: sessionID,
		ClientIP:  clientIP,
		Purpose:   purpose,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	s.tickets[value] = t
	return t, nil
}

// Consume validates and atomically retires a ticket.
//
// The delete happens under the same lock as the lookup, so two concurrent
// upgrades presenting the same ticket cannot both succeed.
func (s *TicketStore) Consume(value, clientIP, purpose string) (Ticket, error) {
	now := s.now()

	s.mu.Lock()
	t, ok := s.tickets[value]
	if ok {
		delete(s.tickets, value)
	}
	s.mu.Unlock()

	if !ok {
		return Ticket{}, ErrTicketUnknown
	}
	if now.After(t.ExpiresAt) {
		return Ticket{}, ErrTicketExpired
	}
	if purpose != "" && t.Purpose != purpose {
		return Ticket{}, ErrTicketMismatch
	}
	// The client address is checked because a ticket that leaks through a proxy
	// log or a shared screen should not be usable from elsewhere. Behind a
	// reverse proxy this relies on AXT_TRUSTED_PROXIES being set correctly.
	if t.ClientIP != "" && clientIP != "" && t.ClientIP != clientIP {
		return Ticket{}, ErrTicketMismatch
	}
	return t, nil
}

// RevokeForSession drops any unconsumed tickets for a session, so closing a
// session cannot be followed by an attachment with a ticket issued moments before.
func (s *TicketStore) RevokeForSession(sessionID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for value, t := range s.tickets {
		if t.SessionID == sessionID {
			delete(s.tickets, value)
			n++
		}
	}
	return n
}

// RevokeForUser drops any unconsumed tickets belonging to a user, called on
// logout and password change.
func (s *TicketStore) RevokeForUser(userID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for value, t := range s.tickets {
		if t.UserID == userID {
			delete(s.tickets, value)
			n++
		}
	}
	return n
}

// Sweep removes expired tickets.
func (s *TicketStore) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
}

func (s *TicketStore) sweepLocked(now time.Time) {
	for value, t := range s.tickets {
		if now.After(t.ExpiresAt) {
			delete(s.tickets, value)
		}
	}
}

// Len reports how many tickets are outstanding, for metrics and tests.
func (s *TicketStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tickets)
}
