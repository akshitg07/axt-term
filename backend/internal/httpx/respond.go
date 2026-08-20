package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Stable, machine-readable error codes. The frontend switches on these; the
// message is for humans and may change.
const (
	CodeBadRequest           = "bad_request"
	CodeValidationFailed     = "validation_failed"
	CodeUnauthenticated      = "unauthenticated"
	CodeForbidden            = "forbidden"
	CodeCSRFFailed           = "csrf_failed"
	CodeOriginRejected       = "origin_rejected"
	CodeNotFound             = "not_found"
	CodeMethodNotAllowed     = "method_not_allowed"
	CodeConflict             = "conflict"
	CodeConfirmationRequired = "confirmation_required"
	CodeAccountLocked        = "account_locked"
	CodePayloadTooLarge      = "payload_too_large"
	CodeUnsupportedMedia     = "unsupported_media_type"
	CodeRateLimited          = "rate_limited"
	CodeInternal             = "internal_error"
	CodeNotImplemented       = "not_implemented"
	CodeUpstreamFailure      = "upstream_failure"
	CodeUpstreamTimeout      = "upstream_timeout"
	CodeUnavailable          = "unavailable"
)

// ErrorBody is the body of every error response.
type ErrorBody struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
}

type errorEnvelope struct {
	Error ErrorBody `json:"error"`
}

// WriteJSON serialises v and writes it with the given status.
//
// The value is marshalled into a buffer before any header is written, so a
// marshalling failure produces a clean 500 rather than a truncated body with a
// 200 status already committed.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"internal_error","message":"failed to encode response"}}` + "\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// NoContent writes a 204.
func NoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// WriteError writes the standard error envelope.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	WriteErrorDetails(w, r, status, code, message, nil)
}

// WriteErrorDetails writes the standard error envelope with structured details.
func WriteErrorDetails(w http.ResponseWriter, r *http.Request, status int, code, message string, details map[string]any) {
	body := ErrorBody{Code: code, Message: message, Details: details}
	if r != nil {
		body.RequestID = RequestID(r.Context())
	}
	WriteJSON(w, status, errorEnvelope{Error: body})
}

// Common shorthands. Handlers call these rather than assembling statuses, so
// the status-to-code mapping stays consistent across the API.

func BadRequest(w http.ResponseWriter, r *http.Request, message string) {
	WriteError(w, r, http.StatusBadRequest, CodeBadRequest, message)
}

func ValidationFailed(w http.ResponseWriter, r *http.Request, fields map[string]any) {
	WriteErrorDetails(w, r, http.StatusUnprocessableEntity, CodeValidationFailed,
		"one or more fields are invalid", map[string]any{"fields": fields})
}

func Unauthenticated(w http.ResponseWriter, r *http.Request) {
	WriteError(w, r, http.StatusUnauthorized, CodeUnauthenticated, "authentication required")
}

func Forbidden(w http.ResponseWriter, r *http.Request, message string) {
	if message == "" {
		message = "you do not have permission to perform this action"
	}
	WriteError(w, r, http.StatusForbidden, CodeForbidden, message)
}

func NotFound(w http.ResponseWriter, r *http.Request, what string) {
	if what == "" {
		what = "resource"
	}
	WriteError(w, r, http.StatusNotFound, CodeNotFound, what+" not found")
}

func Conflict(w http.ResponseWriter, r *http.Request, message string) {
	WriteError(w, r, http.StatusConflict, CodeConflict, message)
}

func Internal(w http.ResponseWriter, r *http.Request) {
	// Deliberately opaque: internal failures are logged with a request id, and
	// the client is given that id rather than an implementation detail.
	WriteError(w, r, http.StatusInternalServerError, CodeInternal,
		"an internal error occurred; quote the request id when reporting it")
}

// NotImplemented is the honest response for a route that exists but whose
// feature has not shipped yet. Used by Coming Soon placeholders so the frontend
// can render an accurate message instead of a generic failure.
func NotImplemented(w http.ResponseWriter, r *http.Request, feature, phase string) {
	WriteErrorDetails(w, r, http.StatusNotImplemented, CodeNotImplemented,
		feature+" is not implemented yet",
		map[string]any{"feature": feature, "phase": phase})
}

// DecodeJSON reads a JSON request body into dst.
//
// Unknown fields are rejected: silently ignoring a misspelled field means a
// user believes they changed a setting that was never applied, and for a tool
// that configures infrastructure that is worse than an error.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType := strings.TrimSpace(strings.Split(ct, ";")[0])
		if !strings.EqualFold(mediaType, "application/json") {
			WriteError(w, r, http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
				"Content-Type must be application/json")
			return errors.New("unsupported media type")
		}
	}

	if maxBytes <= 0 {
		maxBytes = 1 << 20 // 1 MiB is generous for a configuration payload
	}
	body := http.MaxBytesReader(w, r.Body, maxBytes)

	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		writeDecodeError(w, r, err, maxBytes)
		return err
	}
	// A second value in the stream means the client sent something we would
	// silently ignore.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		BadRequest(w, r, "request body must contain exactly one JSON object")
		return errors.New("multiple JSON values in body")
	}
	return nil
}

func writeDecodeError(w http.ResponseWriter, r *http.Request, err error, maxBytes int64) {
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	var maxErr *http.MaxBytesError

	switch {
	case errors.As(err, &syntaxErr):
		BadRequest(w, r, fmt.Sprintf("malformed JSON at byte %d", syntaxErr.Offset))
	case errors.As(err, &typeErr):
		field := typeErr.Field
		if field == "" {
			field = "(body)"
		}
		WriteErrorDetails(w, r, http.StatusUnprocessableEntity, CodeValidationFailed,
			fmt.Sprintf("field %q must be a %s", field, typeErr.Type.String()),
			map[string]any{"fields": map[string]any{field: "expected " + typeErr.Type.String()}})
	case errors.As(err, &maxErr):
		WriteError(w, r, http.StatusRequestEntityTooLarge, CodePayloadTooLarge,
			fmt.Sprintf("request body exceeds %d bytes", maxBytes))
	case errors.Is(err, io.EOF):
		BadRequest(w, r, "request body is empty")
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		field := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
		WriteErrorDetails(w, r, http.StatusUnprocessableEntity, CodeValidationFailed,
			fmt.Sprintf("unknown field %q", field),
			map[string]any{"fields": map[string]any{field: "unknown field"}})
	default:
		BadRequest(w, r, "request body could not be parsed")
	}
}
