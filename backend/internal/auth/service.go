package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/axt-term/axt-term/backend/internal/store"
	"github.com/google/uuid"
)

// Cookie names. The __Host- prefix pins a cookie to the exact origin with no
// subdomain scope and requires Secure, so it is only usable over HTTPS. A
// plain-HTTP deployment falls back to unprefixed names and the startup banner
// warns about it -- silently dropping the cookie instead would make every login
// fail with no explanation.
const (
	SessionCookieName       = "axt_session"
	SessionCookieNameSecure = "__Host-axt_session"
	CSRFCookieName          = "axt_csrf"
	CSRFCookieNameSecure    = "__Host-axt_csrf"
	CSRFHeaderName          = "X-AXT-CSRF"
)

// Service errors.
var (
	ErrInvalidCredentials = errors.New("auth: invalid username or password")
	ErrAccountLocked      = errors.New("auth: account is locked")
	ErrAccountDisabled    = errors.New("auth: account is disabled")
	ErrNoSession          = errors.New("auth: no valid session")
	ErrRateLimited        = errors.New("auth: too many attempts")
)

// Config configures the auth service.
type Config struct {
	IdleTimeout      time.Duration
	MaxLifetime      time.Duration
	CookieSecure     bool
	Argon2           Argon2Params
	TicketTTL        time.Duration
	LoginPerIP       int
	LoginPerUser     int
	LoginWindow      time.Duration
	LockoutThreshold int
	LockoutDuration  time.Duration
	AllowedOrigins   []string
}

// Service performs authentication against the store.
type Service struct {
	store   *store.Store
	cfg     Config
	log     *slog.Logger
	tickets *TicketStore
	limiter *Limiter
	now     func() time.Time
}

// NewService wires the auth service.
func NewService(st *store.Store, cfg Config, log *slog.Logger, now func() time.Time) *Service {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Argon2.MemoryKiB == 0 {
		cfg.Argon2 = DefaultArgon2
	}
	return &Service{
		store:   st,
		cfg:     cfg,
		log:     log,
		tickets: NewTicketStore(cfg.TicketTTL, now),
		limiter: NewLimiter(now),
		now:     now,
	}
}

// Tickets exposes the ticket store so session handlers can issue and consume.
func (s *Service) Tickets() *TicketStore { return s.tickets }

// Limiter exposes the rate limiter for the general API middleware.
func (s *Service) Limiter() *Limiter { return s.limiter }

// Config returns the effective configuration.
func (s *Service) Config() Config { return s.cfg }

// Principal is the authenticated identity attached to a request.
type Principal struct {
	UserID             string
	Username           string
	SessionID          string
	DisplayName        string
	Permissions        map[string]struct{}
	Roles              []string
	MustChangePassword bool
}

// Has reports whether the principal holds a permission.
func (p *Principal) Has(permission string) bool {
	if p == nil {
		return false
	}
	_, ok := p.Permissions[permission]
	return ok
}

// PermissionList returns the permissions as a slice, for the /auth/me response.
func (p *Principal) PermissionList() []string {
	out := make([]string, 0, len(p.Permissions))
	for k := range p.Permissions {
		out = append(out, k)
	}
	return out
}

type principalKey struct{}

// WithPrincipal attaches an authenticated identity to a context.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the authenticated identity, or nil.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}

// LoginInput carries a login attempt.
type LoginInput struct {
	Username  string
	Password  string
	TOTP      string
	ClientIP  string
	UserAgent string
}

// LoginResult carries what the handler needs to set cookies.
type LoginResult struct {
	Principal    *Principal
	SessionToken string
	CSRFToken    string
	ExpiresAt    time.Time
}

// Login verifies credentials and creates a browser session.
//
// The failure path is deliberately uniform: an unknown username, a wrong
// password, and a disabled account all return ErrInvalidCredentials, and an
// unknown username still pays the Argon2 cost so response timing does not
// enumerate accounts.
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	username := strings.TrimSpace(in.Username)
	if username == "" || in.Password == "" {
		return nil, ErrInvalidCredentials
	}

	if in.ClientIP != "" {
		if ok, _ := s.limiter.AllowWindow("login:ip:"+in.ClientIP,
			s.cfg.LoginPerIP, s.cfg.LoginWindow); !ok {
			return nil, ErrRateLimited
		}
	}
	if ok, _ := s.limiter.AllowWindow("login:user:"+strings.ToLower(username),
		s.cfg.LoginPerUser, s.cfg.LoginWindow); !ok {
		return nil, ErrRateLimited
	}

	user, err := s.store.UserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			DummyVerify(in.Password, s.cfg.Argon2)
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if user.IsLocked(s.now()) {
		return nil, ErrAccountLocked
	}
	if !user.IsActive {
		DummyVerify(in.Password, s.cfg.Argon2)
		return nil, ErrInvalidCredentials
	}

	ok, needsRehash, err := VerifyPassword(user.PasswordHash, in.Password, s.cfg.Argon2)
	if err != nil {
		// A corrupt or unrecognised hash must not authenticate anyone, but the
		// operator needs to know it happened.
		s.log.ErrorContext(ctx, "stored password hash could not be parsed",
			slog.String("user_id", user.ID), slog.Any("error", err))
		return nil, ErrInvalidCredentials
	}
	if !ok {
		locked, ferr := s.store.RecordLoginFailure(ctx, user.ID,
			s.cfg.LockoutThreshold, s.cfg.LockoutDuration)
		if ferr != nil {
			s.log.WarnContext(ctx, "could not record login failure", slog.Any("error", ferr))
		}
		if locked {
			s.log.WarnContext(ctx, "account locked after repeated failures",
				slog.String("username", user.Username), slog.String("client_ip", in.ClientIP))
		}
		return nil, ErrInvalidCredentials
	}

	// Upgrade the stored hash transparently when policy has strengthened.
	if needsRehash {
		if newHash, herr := HashPassword(in.Password, s.cfg.Argon2); herr == nil {
			if uerr := s.store.SetPassword(ctx, user.ID, newHash); uerr != nil {
				s.log.WarnContext(ctx, "could not upgrade password hash", slog.Any("error", uerr))
			}
		}
	}

	if err := s.store.RecordLoginSuccess(ctx, user.ID); err != nil {
		s.log.WarnContext(ctx, "could not record login success", slog.Any("error", err))
	}
	s.limiter.ResetWindow("login:user:" + strings.ToLower(username))
	if in.ClientIP != "" {
		s.limiter.ResetWindow("login:ip:" + in.ClientIP)
	}

	return s.createSession(ctx, user, in.ClientIP, in.UserAgent)
}

func (s *Service) createSession(ctx context.Context, user *store.User, clientIP, userAgent string) (*LoginResult, error) {
	sessionToken, sessionHash, err := NewToken()
	if err != nil {
		return nil, err
	}
	csrfToken, csrfHash, err := NewToken()
	if err != nil {
		return nil, err
	}

	now := s.now()
	expiresAt := now.Add(s.cfg.IdleTimeout)
	if absolute := now.Add(s.cfg.MaxLifetime); expiresAt.After(absolute) {
		expiresAt = absolute
	}

	sess := &store.AuthSession{
		ID:         uuid.NewString(),
		UserID:     user.ID,
		TokenHash:  sessionHash,
		CSRFHash:   csrfHash,
		UserAgent:  truncate(userAgent, 512),
		IP:         clientIP,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  expiresAt,
	}
	if err := s.store.CreateAuthSession(ctx, sess); err != nil {
		return nil, err
	}

	principal, err := s.principalFor(ctx, user, sess.ID)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		Principal:    principal,
		SessionToken: sessionToken,
		CSRFToken:    csrfToken,
		ExpiresAt:    expiresAt,
	}, nil
}

func (s *Service) principalFor(ctx context.Context, user *store.User, sessionID string) (*Principal, error) {
	perms, err := s.store.UserPermissions(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		set[p] = struct{}{}
	}
	return &Principal{
		UserID:             user.ID,
		Username:           user.Username,
		SessionID:          sessionID,
		DisplayName:        user.DisplayName,
		Permissions:        set,
		Roles:              user.Roles,
		MustChangePassword: user.MustChangePassword,
	}, nil
}

// ResolveSession turns a session token into a principal, extending the sliding
// expiry. The Authenticate middleware in middleware.go is the HTTP wrapper.
func (s *Service) ResolveSession(ctx context.Context, sessionToken string) (*Principal, *store.AuthSession, error) {
	if sessionToken == "" {
		return nil, nil, ErrNoSession
	}
	sess, err := s.store.AuthSessionByTokenHash(ctx, HashToken(sessionToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, ErrNoSession
		}
		return nil, nil, err
	}

	user, err := s.store.UserByID(ctx, sess.UserID)
	if err != nil {
		return nil, nil, ErrNoSession
	}
	if !user.IsActive {
		// Deactivating an account must take effect immediately, not at the next
		// session expiry.
		_ = s.store.RevokeAuthSession(ctx, sess.ID)
		return nil, nil, ErrAccountDisabled
	}

	now := s.now()
	// Extend only when it has moved meaningfully, so a busy session does not
	// write to the database on every request.
	newExpiry := now.Add(s.cfg.IdleTimeout)
	if absolute := sess.CreatedAt.Add(s.cfg.MaxLifetime); newExpiry.After(absolute) {
		newExpiry = absolute
	}
	if newExpiry.Sub(sess.ExpiresAt) > time.Minute {
		if err := s.store.TouchAuthSession(ctx, sess.ID, newExpiry); err != nil {
			s.log.WarnContext(ctx, "could not extend session", slog.Any("error", err))
		}
		sess.ExpiresAt = newExpiry
	}

	principal, err := s.principalFor(ctx, user, sess.ID)
	if err != nil {
		return nil, nil, err
	}
	return principal, sess, nil
}

// Logout revokes one session and drops any tickets issued from it.
func (s *Service) Logout(ctx context.Context, sessionID, userID string) error {
	s.tickets.RevokeForUser(userID)
	if err := s.store.RevokeAuthSession(ctx, sessionID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// ChangePassword verifies the current password and sets a new one.
//
// Every other session is revoked: after a password change, a session an attacker
// already holds must stop working, or the change accomplishes nothing.
func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword, keepSessionID string) error {
	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	ok, _, err := VerifyPassword(user.PasswordHash, currentPassword, s.cfg.Argon2)
	if err != nil || !ok {
		return ErrInvalidCredentials
	}
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	if currentPassword == newPassword {
		return errors.New("auth: the new password must differ from the current one")
	}

	hash, err := HashPassword(newPassword, s.cfg.Argon2)
	if err != nil {
		return err
	}
	if err := s.store.SetPassword(ctx, userID, hash); err != nil {
		return err
	}

	s.tickets.RevokeForUser(userID)
	revoked, err := s.store.RevokeUserSessions(ctx, userID, keepSessionID)
	if err != nil {
		return err
	}
	if revoked > 0 {
		s.log.InfoContext(ctx, "revoked other sessions after password change",
			slog.String("user_id", userID), slog.Int("revoked", revoked))
	}
	return nil
}

// SetPasswordAsAdmin sets a password without knowing the current one and forces a
// change at next login.
func (s *Service) SetPasswordAsAdmin(ctx context.Context, userID, newPassword string, requireChange bool) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	hash, err := HashPassword(newPassword, s.cfg.Argon2)
	if err != nil {
		return err
	}
	if err := s.store.SetPassword(ctx, userID, hash); err != nil {
		return err
	}
	if requireChange {
		if err := s.store.SetMustChangePassword(ctx, userID, true); err != nil {
			return err
		}
	}
	s.tickets.RevokeForUser(userID)
	if _, err := s.store.RevokeUserSessions(ctx, userID, ""); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------- cookies ---

// SessionCookieName returns the cookie name in use, which depends on whether the
// deployment is served over TLS.
func (c Config) SessionCookieName() string {
	if c.CookieSecure {
		return SessionCookieNameSecure
	}
	return SessionCookieName
}

// CSRFCookieName returns the CSRF cookie name in use.
func (c Config) CSRFCookieName() string {
	if c.CookieSecure {
		return CSRFCookieNameSecure
	}
	return CSRFCookieName
}

// SetSessionCookies writes the session and CSRF cookies.
//
// The session cookie is HttpOnly so injected script cannot read it. The CSRF
// cookie deliberately is not: being readable by our own JavaScript is the
// mechanism, and on its own it authenticates nothing.
func (s *Service) SetSessionCookies(w http.ResponseWriter, r *LoginResult) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.SessionCookieName(),
		Value:    r.SessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  r.ExpiresAt,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CSRFCookieName(),
		Value:    r.CSRFToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  r.ExpiresAt,
	})
}

// ClearSessionCookies expires both cookies.
func (s *Service) ClearSessionCookies(w http.ResponseWriter) {
	for _, name := range []string{s.cfg.SessionCookieName(), s.cfg.CSRFCookieName()} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: name == s.cfg.SessionCookieName(),
			Secure:   s.cfg.CookieSecure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}
}

// SessionTokenFromRequest reads the session cookie.
func (s *Service) SessionTokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(s.cfg.SessionCookieName()); err == nil {
		return c.Value
	}
	// Tolerate the other name so a deployment that gains or loses TLS does not
	// invalidate every live session on restart.
	other := SessionCookieName
	if !s.cfg.CookieSecure {
		other = SessionCookieNameSecure
	}
	if c, err := r.Cookie(other); err == nil {
		return c.Value
	}
	return ""
}

// Sweep discards expired tickets, stale rate-limit entries, and expired session
// rows. Called periodically by the server's background loop.
func (s *Service) Sweep(ctx context.Context) {
	s.tickets.Sweep()
	s.limiter.Sweep(15 * time.Minute)
	cutoff := s.now().Add(-24 * time.Hour)
	if n, err := s.store.PurgeExpiredAuthSessions(ctx, cutoff); err != nil {
		s.log.WarnContext(ctx, "could not purge expired sessions", slog.Any("error", err))
	} else if n > 0 {
		s.log.Debug("purged expired sessions", slog.Int("count", n))
	}
}

// BootstrapAdmin creates the first administrator when no users exist.
//
// Returns the generated password when one was not supplied, so `axt-admin` can
// print it exactly once.
func (s *Service) BootstrapAdmin(ctx context.Context, username, password string) (generatedPassword string, err error) {
	count, err := s.store.CountUsers(ctx)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", fmt.Errorf("auth: refusing to bootstrap: %d user(s) already exist", count)
	}
	if password == "" {
		password, err = GeneratePassword(24)
		if err != nil {
			return "", err
		}
		generatedPassword = password
	}
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	hash, err := HashPassword(password, s.cfg.Argon2)
	if err != nil {
		return "", err
	}
	user := &store.User{
		ID:           uuid.NewString(),
		Username:     username,
		DisplayName:  username,
		PasswordHash: hash,
		IsActive:     true,
		// A generated password must be changed; an operator-supplied one is
		// assumed deliberate.
		MustChangePassword: generatedPassword != "",
	}
	if err := s.store.CreateUser(ctx, user, []string{"admin"}); err != nil {
		return "", err
	}
	return generatedPassword, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
