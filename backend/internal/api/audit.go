package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/axt-term/axt-term/backend/internal/auth"
	"github.com/axt-term/axt-term/backend/internal/httpx"
	"github.com/axt-term/axt-term/backend/internal/store"
)

// Audit action keys. Grouped by prefix so the audit UI can filter on "session."
// or "file." without a separate category column.
const (
	ActionLoginSuccess   = "auth.login"
	ActionLoginFailure   = "auth.login.failed"
	ActionLogout         = "auth.logout"
	ActionPasswordChange = "auth.password.change"
	ActionSessionRevoke  = "auth.session.revoke"

	ActionHostCreate    = "host.create"
	ActionHostUpdate    = "host.update"
	ActionHostDelete    = "host.delete"
	ActionHostTest      = "host.test"
	ActionFolderCreate  = "folder.create"
	ActionFolderUpdate  = "folder.update"
	ActionFolderDelete  = "folder.delete"
	ActionTagCreate     = "tag.create"
	ActionTagDelete     = "tag.delete"
	ActionHostKeyTrust  = "hostkey.trust"
	ActionHostKeyRevoke = "hostkey.revoke"

	ActionCredentialCreate = "credential.create"
	ActionCredentialUpdate = "credential.update"
	ActionCredentialDelete = "credential.delete"

	ActionSessionOpen      = "session.open"
	ActionSessionClose     = "session.close"
	ActionSessionFailed    = "session.failed"
	ActionSessionRecording = "session.recording"
	// Deleting a Recent entry removes a convenience row, never an audit row, and is
	// itself recorded so the removal is visible.
	ActionSessionHistoryDelete = "session.history.delete"

	ActionFileRead    = "file.read"
	ActionFileWrite   = "file.write"
	ActionFileDelete  = "file.delete"
	ActionFileRename  = "file.rename"
	ActionFileChmod   = "file.chmod"
	ActionFileUpload  = "file.upload"
	ActionFileDownlod = "file.download"

	ActionSnippetCreate = "snippet.create"
	ActionSnippetUpdate = "snippet.update"
	ActionSnippetDelete = "snippet.delete"

	ActionSettingsUpdate = "settings.update"
	ActionPermissionDeny = "authz.denied"
)

// Auditor writes audit entries from a request context.
//
// Failures are logged and swallowed: refusing a user's action because the audit
// write failed would turn a logging problem into an outage. The log line is the
// backstop, and a persistent failure is visible there.
type Auditor struct {
	store *store.Store
	log   *slog.Logger
}

// NewAuditor creates the auditor.
func NewAuditor(st *store.Store, log *slog.Logger) *Auditor {
	return &Auditor{store: st, log: log}
}

// Entry describes one event to record.
type Entry struct {
	Action   string
	Target   string
	Result   store.AuditResult
	Severity store.AuditSeverity
	Host     *store.Host
	Detail   map[string]any
	// Username overrides the principal's name, for a failed login where there is
	// no principal yet.
	Username string
}

// Record writes an entry, taking identity and request metadata from r.
func (a *Auditor) Record(r *http.Request, e Entry) {
	if e.Result == "" {
		e.Result = store.AuditSuccess
	}
	if e.Severity == "" {
		e.Severity = store.SeverityInfo
	}

	event := &store.AuditEvent{
		Timestamp: time.Now().UTC(),
		Username:  e.Username,
		Action:    e.Action,
		Target:    e.Target,
		Result:    e.Result,
		Severity:  e.Severity,
		ClientIP:  httpx.ClientIP(r.Context()),
		RequestID: httpx.RequestID(r.Context()),
		Detail:    e.Detail,
	}

	if p := auth.PrincipalFrom(r.Context()); p != nil {
		event.UserID = p.UserID
		if event.Username == "" {
			event.Username = p.Username
		}
		event.AuthSessionID = p.SessionID
	}
	if e.Host != nil {
		event.HostID = e.Host.ID
		event.HostSnapshot = e.Host.Label()
	}

	// A short independent context: the request may already be cancelled by the
	// time a failure is being recorded, and that must not lose the record.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
	defer cancel()

	if err := a.store.RecordAudit(ctx, event); err != nil {
		a.log.ErrorContext(ctx, "could not write audit entry",
			slog.String("action", e.Action),
			slog.Any("error", err))
	}
}

// Success is shorthand for a successful action.
func (a *Auditor) Success(r *http.Request, action, target string, detail map[string]any) {
	a.Record(r, Entry{Action: action, Target: target, Result: store.AuditSuccess, Detail: detail})
}

// Failure is shorthand for a failed action.
func (a *Auditor) Failure(r *http.Request, action, target string, err error) {
	detail := map[string]any{}
	if err != nil {
		detail["error"] = err.Error()
	}
	a.Record(r, Entry{
		Action: action, Target: target,
		Result: store.AuditFailure, Severity: store.SeverityWarning, Detail: detail,
	})
}

// HostAction is shorthand for an action against a host.
func (a *Auditor) HostAction(r *http.Request, host *store.Host, action, target string, detail map[string]any) {
	a.Record(r, Entry{Action: action, Target: target, Host: host, Detail: detail})
}
