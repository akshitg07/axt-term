package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/axt-term/axt-term/backend/internal/auth"
	"github.com/axt-term/axt-term/backend/internal/httpx"
	"github.com/axt-term/axt-term/backend/internal/store"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp,omitempty"`
}

type userResponse struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	DisplayName        string     `json:"display_name"`
	Email              string     `json:"email,omitempty"`
	Roles              []string   `json:"roles"`
	Permissions        []string   `json:"permissions"`
	MustChangePassword bool       `json:"must_change_password"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
}

func principalResponse(p *auth.Principal) userResponse {
	return userResponse{
		ID:                 p.UserID,
		Username:           p.Username,
		DisplayName:        p.DisplayName,
		Roles:              p.Roles,
		Permissions:        p.PermissionList(),
		MustChangePassword: p.MustChangePassword,
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decode(w, r, &req) {
		return
	}

	result, err := s.auth.Login(r.Context(), auth.LoginInput{
		Username:  req.Username,
		Password:  req.Password,
		TOTP:      req.TOTP,
		ClientIP:  httpx.ClientIP(r.Context()),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		s.audit.Record(r, Entry{
			Action:   ActionLoginFailure,
			Target:   req.Username,
			Username: req.Username,
			Result:   store.AuditFailure,
			Severity: store.SeverityWarning,
			Detail:   map[string]any{"reason": loginFailureReason(err)},
		})

		switch {
		case errors.Is(err, auth.ErrRateLimited):
			w.Header().Set("Retry-After", "60")
			httpx.WriteError(w, r, http.StatusTooManyRequests, httpx.CodeRateLimited,
				"too many login attempts; wait a minute and try again")
		case errors.Is(err, auth.ErrAccountLocked):
			httpx.WriteError(w, r, http.StatusLocked, httpx.CodeAccountLocked,
				"this account is temporarily locked after repeated failed attempts")
		case errors.Is(err, auth.ErrInvalidCredentials):
			// Deliberately identical for an unknown user, a wrong password, and a
			// disabled account: distinguishing them enumerates valid accounts.
			httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeUnauthenticated,
				"incorrect username or password")
		default:
			s.fail(w, r, err)
		}
		return
	}

	s.auth.SetSessionCookies(w, result)
	s.audit.Record(r, Entry{
		Action:   ActionLoginSuccess,
		Target:   result.Principal.Username,
		Username: result.Principal.Username,
		Detail:   map[string]any{"user_id": result.Principal.UserID},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"user":       principalResponse(result.Principal),
		"expires_at": result.ExpiresAt,
	})
}

// loginFailureReason records why a login failed without recording the attempted
// password or anything derived from it.
func loginFailureReason(err error) string {
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		return "rate_limited"
	case errors.Is(err, auth.ErrAccountLocked):
		return "locked"
	case errors.Is(err, auth.ErrAccountDisabled):
		return "disabled"
	case errors.Is(err, auth.ErrInvalidCredentials):
		return "invalid_credentials"
	default:
		return "error"
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	if p != nil {
		if err := s.auth.Logout(r.Context(), p.SessionID, p.UserID); err != nil {
			s.fail(w, r, err)
			return
		}
		// Live sessions are deliberately left running: logging out of the browser
		// is not the same as abandoning a long-running command, and the session
		// idle timeout reclaims them.
		s.audit.Success(r, ActionLogout, p.Username, nil)
	}
	s.auth.ClearSessionCookies(w)
	httpx.NoContent(w)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	if p == nil {
		httpx.Unauthenticated(w, r)
		return
	}
	user, err := s.store.UserByID(r.Context(), p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	resp := principalResponse(p)
	resp.Email = user.Email
	resp.DisplayName = user.DisplayName
	resp.LastLoginAt = user.LastLoginAt

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"user":         resp,
		"instance":     s.cfg.HTTP.PublicURL.String(),
		"rdp_enabled":  s.cfg.RDP.Enabled(),
		"live_sessions": len(s.sessions.ListForUser(p.UserID)),
	})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	var req changePasswordRequest
	if !decode(w, r, &req) {
		return
	}

	err := s.auth.ChangePassword(r.Context(), p.UserID, req.CurrentPassword, req.NewPassword, p.SessionID)
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrInvalidCredentials):
		s.audit.Failure(r, ActionPasswordChange, p.Username, err)
		httpx.ValidationFailed(w, r, map[string]any{"current_password": "incorrect"})
		return
	case errors.Is(err, auth.ErrPasswordTooShort), errors.Is(err, auth.ErrPasswordTooLong):
		httpx.ValidationFailed(w, r, map[string]any{"new_password": err.Error()})
		return
	default:
		// A "must differ" style rejection is a validation problem, not a server
		// failure, and the message is safe to show.
		httpx.ValidationFailed(w, r, map[string]any{"new_password": err.Error()})
		return
	}

	s.audit.Record(r, Entry{
		Action:   ActionPasswordChange,
		Target:   p.Username,
		Severity: store.SeverityNotice,
		Detail:   map[string]any{"other_sessions_revoked": true},
	})
	httpx.NoContent(w)
}

func (s *Server) handleListAuthSessions(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	sessions, err := s.store.ListAuthSessions(r.Context(), p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	type row struct {
		ID         string    `json:"id"`
		UserAgent  string    `json:"user_agent"`
		IP         string    `json:"ip"`
		CreatedAt  time.Time `json:"created_at"`
		LastSeenAt time.Time `json:"last_seen_at"`
		ExpiresAt  time.Time `json:"expires_at"`
		Current    bool      `json:"current"`
	}
	out := make([]row, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, row{
			ID:         sess.ID,
			UserAgent:  sess.UserAgent,
			IP:         sess.IP,
			CreatedAt:  sess.CreatedAt,
			LastSeenAt: sess.LastSeenAt,
			ExpiresAt:  sess.ExpiresAt,
			Current:    sess.ID == p.SessionID,
		})
	}
	writeList(w, out, len(out))
}

func (s *Server) handleRevokeAuthSession(w http.ResponseWriter, r *http.Request) {
	p := s.principal(r)
	id := r.PathValue("id")

	// Ownership is enforced by listing the user's own sessions rather than
	// trusting the id, so one user cannot revoke another's session.
	sessions, err := s.store.ListAuthSessions(r.Context(), p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	owned := false
	for _, sess := range sessions {
		if sess.ID == id {
			owned = true
			break
		}
	}
	if !owned {
		httpx.NotFound(w, r, "session")
		return
	}

	if err := s.store.RevokeAuthSession(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.Success(r, ActionSessionRevoke, id, nil)
	httpx.NoContent(w)
}
