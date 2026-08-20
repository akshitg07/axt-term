package auth

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/axt-term/axt-term/backend/internal/httpx"
)

// Middleware layers, in the order they run:
//
//	RequireOrigin  -> rejects cross-site requests before anything else happens
//	Authenticate   -> resolves the session cookie into a Principal
//	RequireCSRF    -> double-submit check on state-changing requests
//	RateLimit      -> per-user throttling
//	Authorize      -> per-route permission check
//
// Each is independent and fails closed.

// RequireOrigin rejects requests whose Origin is not in the allow-list.
//
// This is checked in addition to SameSite cookies and the CSRF token because each
// fails differently: SameSite depends on browser behaviour, the CSRF token
// depends on JavaScript running, and the Origin header is asserted by the browser
// itself. A request with no Origin and no Sec-Fetch-Site is allowed through --
// that is a same-origin navigation or a non-browser client, and the CSRF check
// still applies to it.
func RequireOrigin(allowed []string, log *slog.Logger) httpx.Middleware {
	index := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		index[strings.ToLower(strings.TrimRight(o, "/"))] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
				log.WarnContext(r.Context(), "rejected cross-site request",
					slog.String("path", r.URL.Path),
					slog.String("client_ip", httpx.ClientIP(r.Context())))
				httpx.WriteError(w, r, http.StatusForbidden, httpx.CodeOriginRejected,
					"cross-site requests are not accepted")
				return
			}

			origin := r.Header.Get("Origin")
			if origin == "" && !isStateChanging(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			if origin == "" {
				// Fall back to Referer for state-changing requests, which older
				// clients and some proxies still send in preference to Origin.
				if ref := r.Header.Get("Referer"); ref != "" {
					origin = originOfURL(ref)
				}
			}
			if origin == "" {
				// No origin information at all on a state-changing request. The
				// CSRF token is the remaining defence, and it is mandatory.
				next.ServeHTTP(w, r)
				return
			}
			if _, ok := index[strings.ToLower(strings.TrimRight(origin, "/"))]; !ok {
				log.WarnContext(r.Context(), "rejected request from unrecognised origin",
					slog.String("origin", origin),
					slog.String("path", r.URL.Path),
					slog.String("client_ip", httpx.ClientIP(r.Context())))
				httpx.WriteError(w, r, http.StatusForbidden, httpx.CodeOriginRejected,
					"this origin is not permitted; check AXT_PUBLIC_URL and AXT_ALLOWED_ORIGINS")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// originOfURL extracts scheme://host from an absolute URL, without importing
// net/url for one field.
func originOfURL(raw string) string {
	idx := strings.Index(raw, "://")
	if idx < 0 {
		return ""
	}
	rest := raw[idx+3:]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}
	if rest == "" {
		return ""
	}
	return raw[:idx] + "://" + rest
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// Authenticate resolves the session cookie and attaches a Principal.
//
// It does not reject unauthenticated requests: public routes exist, and rejecting
// is the job of Authorize, which knows what the route requires.
func (s *Service) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := s.SessionTokenFromRequest(r)
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}

		principal, _, err := s.ResolveSession(r.Context(), token)
		switch {
		case err == nil:
			r = r.WithContext(WithPrincipal(r.Context(), principal))
		case errors.Is(err, ErrNoSession), errors.Is(err, ErrAccountDisabled):
			// An expired or revoked cookie is cleared so the browser stops
			// sending it and the login screen does not appear to be broken.
			s.ClearSessionCookies(w)
		default:
			s.log.ErrorContext(r.Context(), "session lookup failed", slog.Any("error", err))
			httpx.Internal(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireCSRF enforces the double-submit token on state-changing requests.
//
// Both halves are checked: the header must match the cookie, and the cookie must
// match the hash stored with the session. The second check is what stops a token
// from a revoked session being replayed.
func (s *Service) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isStateChanging(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		principal := PrincipalFrom(r.Context())
		if principal == nil {
			// Unauthenticated state-changing requests (login) have no session to
			// bind a token to; the origin check covers them.
			next.ServeHTTP(w, r)
			return
		}

		header := r.Header.Get(CSRFHeaderName)
		cookie, err := r.Cookie(s.cfg.CSRFCookieName())
		if err != nil || header == "" {
			httpx.WriteError(w, r, http.StatusForbidden, httpx.CodeCSRFFailed,
				"missing CSRF token; reload the page and try again")
			return
		}
		if subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) != 1 {
			httpx.WriteError(w, r, http.StatusForbidden, httpx.CodeCSRFFailed,
				"CSRF token mismatch; reload the page and try again")
			return
		}

		sess, err := s.store.AuthSessionByTokenHash(r.Context(), HashToken(s.SessionTokenFromRequest(r)))
		if err != nil {
			httpx.Unauthenticated(w, r)
			return
		}
		if subtle.ConstantTimeCompare(HashToken(cookie.Value), sess.CSRFHash) != 1 {
			httpx.WriteError(w, r, http.StatusForbidden, httpx.CodeCSRFFailed,
				"CSRF token does not belong to this session")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimit throttles authenticated requests per user and anonymous ones per
// client address.
func (s *Service) RateLimit(perMinute, burst int) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := "ip:" + httpx.ClientIP(r.Context())
			if p := PrincipalFrom(r.Context()); p != nil {
				key = "user:" + p.UserID
			}
			if !s.limiter.Allow(key, perMinute, burst) {
				w.Header().Set("Retry-After", "1")
				httpx.WriteError(w, r, http.StatusTooManyRequests, httpx.CodeRateLimited,
					"too many requests; slow down")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Authorize enforces the route's declared protection.
//
// Route access is declared in the route table and validated at startup, so a
// route that reaches this middleware always states what it needs.
func Authorize(access httpx.Access, permission string) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if access == httpx.AccessPublic {
				next.ServeHTTP(w, r)
				return
			}
			principal := PrincipalFrom(r.Context())
			if principal == nil {
				httpx.Unauthenticated(w, r)
				return
			}
			if access == httpx.AccessPermission && !principal.Has(permission) {
				httpx.WriteErrorDetails(w, r, http.StatusForbidden, httpx.CodeForbidden,
					"this action requires the "+permission+" permission",
					map[string]any{"required_permission": permission})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePasswordChange blocks normal API use while a password change is
// outstanding, allowing only the endpoints needed to perform it.
//
// Without this, an account created with a generated password could be used
// indefinitely without ever changing it, which defeats the point of the flag.
func RequirePasswordChange(next http.Handler) http.Handler {
	allowed := map[string]bool{
		"/api/v1/auth/me":       true,
		"/api/v1/auth/password": true,
		"/api/v1/auth/logout":   true,
		"/api/v1/version":       true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFrom(r.Context())
		if p == nil || !p.MustChangePassword || allowed[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		httpx.WriteErrorDetails(w, r, http.StatusForbidden, httpx.CodeForbidden,
			"you must change your password before continuing",
			map[string]any{"must_change_password": true})
	})
}
