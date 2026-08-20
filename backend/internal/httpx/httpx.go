// Package httpx holds AXT-Term's HTTP plumbing: the server, the router, the
// middleware chain, and the single response/error shape every handler uses.
//
// Middleware, routing, and responses live in one package on purpose. The panic
// recoverer must write a JSON error, and the router must accept middleware, so
// splitting them into sibling packages produces an import cycle for no
// architectural gain.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware to a handler. The first entry is outermost, so
// Chain(h, A, B) yields A(B(h)) and requests traverse A before B.
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		if mw[i] != nil {
			h = mw[i](h)
		}
	}
	return h
}

type contextKey int

const (
	ctxRequestID contextKey = iota
	ctxClientIP
)

// WithRequestID stores a request identifier for logging and error responses.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxRequestID, id)
}

// RequestID returns the request identifier, or "" if none was set.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxRequestID).(string)
	return id
}

// WithClientIP stores the resolved client address.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ctxClientIP, ip)
}

// ClientIP returns the resolved client address, or "" if none was set.
//
// This is the address recorded in audit entries, so it must be the real client
// rather than a reverse proxy. See RealIP for how it is determined.
func ClientIP(ctx context.Context) string {
	ip, _ := ctx.Value(ctxClientIP).(string)
	return ip
}

// newID returns a short random identifier for request correlation.
func newID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice, and a request identifier is
		// not a security boundary. Degrade rather than refuse the request.
		return "unidentified"
	}
	return hex.EncodeToString(b[:])
}
