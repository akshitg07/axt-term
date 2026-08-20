// Package store holds AXT-Term's domain types and their SQLite-backed
// persistence.
//
// Models and implementation live together, and services declare the narrow
// interfaces they need where they consume them. That is the Go convention
// ("accept interfaces, return structs") and it keeps the surface honest: a
// PostgreSQL variant means adding dialect handling here, not satisfying a
// speculative interface layer written in advance. See ADR 0002 for when that
// becomes worth doing.
//
// Conventions:
//   - IDs are UUIDv4 text, stable across export and import.
//   - Timestamps are stored as RFC 3339 UTC text and exposed as time.Time.
//   - Nullable timestamps are *time.Time; other nullable columns use zero values,
//     because an empty string is what the UI renders anyway and a pointer per
//     field would triple the null checks for no benefit.
//   - Secret material never appears in a struct with a JSON tag.
package store

import (
	"net"
	"strconv"
	"time"
)

// ---------------------------------------------------------------- identity ---

// User is an AXT-Term account.
type User struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	Email              string     `json:"email"`
	DisplayName        string     `json:"display_name"`
	IsActive           bool       `json:"is_active"`
	MustChangePassword bool       `json:"must_change_password"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	Roles              []string   `json:"roles"`

	// Never serialised. PasswordHash is an Argon2id encoded string, which is not
	// a secret in the same sense as a credential but is still not something to
	// hand to a browser.
	PasswordHash     string     `json:"-"`
	TOTPSecretEnc    []byte     `json:"-"`
	FailedLoginCount int        `json:"-"`
	LockedUntil      *time.Time `json:"-"`
}

// IsLocked reports whether the account is currently locked out.
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

// Role groups permissions.
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IsBuiltin   bool     `json:"is_builtin"`
	Permissions []string `json:"permissions,omitempty"`
}

// Permission is a single capability key such as "host.write".
type Permission struct {
	Key         string `json:"key"`
	Description string `json:"description"`
}

// AuthSession is a browser session. The cookie value is never stored, only its
// hash, so a stolen database yields no usable tokens.
type AuthSession struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	UserAgent  string     `json:"user_agent"`
	IP         string     `json:"ip"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`

	TokenHash []byte `json:"-"`
	CSRFHash  []byte `json:"-"`
}

// --------------------------------------------------------------- inventory ---

// Protocol identifies how a host is reached. Values beyond ssh/sftp/rdp are
// accepted by the schema from the start, so adding VNC means writing an engine
// rather than migrating the inventory.
type Protocol string

const (
	ProtocolSSH    Protocol = "ssh"
	ProtocolSFTP   Protocol = "sftp"
	ProtocolRDP    Protocol = "rdp"
	ProtocolVNC    Protocol = "vnc"
	ProtocolTelnet Protocol = "telnet"
	ProtocolSerial Protocol = "serial"
	ProtocolWinRM  Protocol = "winrm"
)

// DefaultPort returns the conventional port for a protocol, used when a host is
// created without one.
func (p Protocol) DefaultPort() int {
	switch p {
	case ProtocolSSH, ProtocolSFTP:
		return 22
	case ProtocolRDP:
		return 3389
	case ProtocolVNC:
		return 5900
	case ProtocolTelnet:
		return 23
	case ProtocolWinRM:
		return 5986
	default:
		return 0
	}
}

// Valid reports whether the protocol is one the schema accepts.
func (p Protocol) Valid() bool {
	switch p {
	case ProtocolSSH, ProtocolSFTP, ProtocolRDP, ProtocolVNC,
		ProtocolTelnet, ProtocolSerial, ProtocolWinRM:
		return true
	}
	return false
}

// Implemented reports whether a session of this protocol can actually be opened
// by this build. Everything else is inventory-only and the UI labels it.
func (p Protocol) Implemented() bool {
	switch p {
	case ProtocolSSH, ProtocolSFTP, ProtocolRDP:
		return true
	}
	return false
}

// OSFamily narrows which contextual actions a host offers.
type OSFamily string

const (
	OSLinux   OSFamily = "linux"
	OSWindows OSFamily = "windows"
	OSBSD     OSFamily = "bsd"
	OSMacOS   OSFamily = "macos"
	OSNetwork OSFamily = "network"
	OSUnknown OSFamily = "unknown"
)

// Valid reports whether the OS family is one the schema accepts.
func (o OSFamily) Valid() bool {
	switch o {
	case OSLinux, OSWindows, OSBSD, OSMacOS, OSNetwork, OSUnknown:
		return true
	}
	return false
}

// AuthMethod selects how a host authenticates.
type AuthMethod string

const (
	// AuthCredential uses the referenced credential profile.
	AuthCredential AuthMethod = "credential"
	// AuthAgent uses the SSH agent socket the operator mounted.
	AuthAgent AuthMethod = "agent"
	// AuthPasswordPrompt asks the user at connect time and stores nothing.
	AuthPasswordPrompt AuthMethod = "password_prompt"
	// AuthKeyPrompt asks for a key passphrase at connect time.
	AuthKeyPrompt AuthMethod = "key_prompt"
)

// Valid reports whether the auth method is one the schema accepts.
func (a AuthMethod) Valid() bool {
	switch a {
	case AuthCredential, AuthAgent, AuthPasswordPrompt, AuthKeyPrompt:
		return true
	}
	return false
}

// CommandLogging is the per-host override of the instance default.
type CommandLogging string

const (
	LoggingInherit  CommandLogging = "inherit"
	LoggingOff      CommandLogging = "off"
	LoggingCommands CommandLogging = "commands"
	LoggingFull     CommandLogging = "full"
)

// Valid reports whether the value is one the schema accepts.
func (c CommandLogging) Valid() bool {
	switch c {
	case LoggingInherit, LoggingOff, LoggingCommands, LoggingFull:
		return true
	}
	return false
}

// Folder organises hosts. Folders nest.
type Folder struct {
	ID        string    `json:"id"`
	ParentID  string    `json:"parent_id"`
	Name      string    `json:"name"`
	Icon      string    `json:"icon"`
	Color     string    `json:"color"`
	SortOrder int       `json:"sort_order"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Host is one machine in the inventory.
type Host struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Hostname     string     `json:"hostname"`
	Port         int        `json:"port"`
	Protocol     Protocol   `json:"protocol"`
	FolderID     string     `json:"folder_id"`
	Username     string     `json:"username"`
	AuthMethod   AuthMethod `json:"auth_method"`
	CredentialID string     `json:"credential_id"`
	JumpHostID   string     `json:"jump_host_id"`
	OSFamily     OSFamily   `json:"os_family"`
	Color        string     `json:"color"`
	Icon         string     `json:"icon"`
	Notes        string     `json:"notes"`
	IsFavorite   bool       `json:"is_favorite"`
	SortOrder    int        `json:"sort_order"`

	HealthCheckEnabled   bool `json:"health_check_enabled"`
	HealthCheckIntervalS int  `json:"health_check_interval_s"`

	CommandLogging CommandLogging `json:"command_logging"`
	RDPOptions     RDPOptions     `json:"rdp_options"`

	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Joined for convenience in list views.
	Tags       []string    `json:"tags"`
	FolderPath string      `json:"folder_path,omitempty"`
	Health     *HostHealth `json:"health,omitempty"`
}

// Address renders host:port.
func (h *Host) Address() string { return joinHostPort(h.Hostname, h.Port) }

// Label renders the form used in audit snapshots and session history, which must
// stay readable after the host row is deleted.
func (h *Host) Label() string {
	if h.Username != "" {
		return h.Name + " (" + h.Username + "@" + h.Address() + ")"
	}
	return h.Name + " (" + h.Address() + ")"
}

// RDPOptions carries per-host RDP settings. Clipboard and drive redirection are
// off by default: each is a bidirectional data path into a Windows host and
// should be a decision rather than an accident.
type RDPOptions struct {
	Domain            string `json:"domain,omitempty"`
	Security          string `json:"security,omitempty"` // any, nla, tls, rdp
	IgnoreCert        bool   `json:"ignore_cert,omitempty"`
	EnableClipboard   bool   `json:"enable_clipboard,omitempty"`
	EnableDrive       bool   `json:"enable_drive,omitempty"`
	DrivePath         string `json:"drive_path,omitempty"`
	EnableAudio       bool   `json:"enable_audio,omitempty"`
	EnablePrinting    bool   `json:"enable_printing,omitempty"`
	InitialWidth      int    `json:"initial_width,omitempty"`
	InitialHeight     int    `json:"initial_height,omitempty"`
	ColorDepth        int    `json:"color_depth,omitempty"`
	DisableWallpaper  bool   `json:"disable_wallpaper,omitempty"`
	ResizeMethod      string `json:"resize_method,omitempty"` // display-update, reconnect
	RemoteApp         string `json:"remote_app,omitempty"`
	PreconnectionBlob string `json:"preconnection_blob,omitempty"`
}

// Tag is a free-form host label.
type Tag struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
	Count int    `json:"count,omitempty"`
}

// HealthStatus is a host's last observed reachability.
type HealthStatus string

const (
	HealthOnline  HealthStatus = "online"
	HealthSlow    HealthStatus = "slow"
	HealthOffline HealthStatus = "offline"
	HealthUnknown HealthStatus = "unknown"
)

// HostHealth is the result of the most recent check.
type HostHealth struct {
	HostID    string       `json:"host_id"`
	Status    HealthStatus `json:"status"`
	LatencyMS *int         `json:"latency_ms,omitempty"`
	CheckedAt time.Time    `json:"checked_at"`
	Error     string       `json:"error,omitempty"`
}

// HostKey is a trusted SSH host key. Keyed by hostname and port rather than host
// id, so the same machine reached through two inventory entries shares one trust
// decision.
type HostKey struct {
	ID                string     `json:"id"`
	Hostname          string     `json:"hostname"`
	Port              int        `json:"port"`
	KeyType           string     `json:"key_type"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	PublicKey         []byte     `json:"-"`
	FirstSeenAt       time.Time  `json:"first_seen_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	TrustedBy         string     `json:"trusted_by"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
}

// ------------------------------------------------------------- credentials ---

// CredentialKind selects what a credential holds.
type CredentialKind string

const (
	CredPassword    CredentialKind = "password"
	CredSSHKey      CredentialKind = "ssh_key"
	CredSSHAgent    CredentialKind = "ssh_agent"
	CredRDPPassword CredentialKind = "rdp_password"
)

// Valid reports whether the kind is one the schema accepts.
func (k CredentialKind) Valid() bool {
	switch k {
	case CredPassword, CredSSHKey, CredSSHAgent, CredRDPPassword:
		return true
	}
	return false
}

// CredentialProvider is where the secret actually lives. Anything other than
// local means AXT-Term holds a reference rather than ciphertext.
type CredentialProvider string

const (
	ProviderLocal       CredentialProvider = "local"
	ProviderVault       CredentialProvider = "vault"
	ProviderBitwarden   CredentialProvider = "bitwarden"
	ProviderOnePassword CredentialProvider = "onepassword"
	ProviderEnv         CredentialProvider = "env"
)

// Implemented reports whether this build can resolve the provider.
func (p CredentialProvider) Implemented() bool { return p == ProviderLocal }

// Credential is a credential profile.
//
// There is deliberately no field for a secret value. The absence is the
// enforcement: an endpoint cannot accidentally serialise a password because the
// response type has nowhere to put one.
type Credential struct {
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	Kind           CredentialKind     `json:"kind"`
	Provider       CredentialProvider `json:"provider"`
	ExternalRef    string             `json:"external_ref,omitempty"`
	Username       string             `json:"username"`
	Domain         string             `json:"domain,omitempty"`
	KeyType        string             `json:"key_type,omitempty"`
	KeyFingerprint string             `json:"key_fingerprint,omitempty"`
	KeyComment     string             `json:"key_comment,omitempty"`
	Notes          string             `json:"notes"`
	KeyVersion     int                `json:"key_version"`

	// Which secret fields are populated, so the UI can show "password set"
	// without ever reading one.
	HasPassword   bool `json:"has_password"`
	HasPrivateKey bool `json:"has_private_key"`
	HasPassphrase bool `json:"has_passphrase"`

	InUseByCount int        `json:"in_use_by_count"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`

	// DEKWrapped is the credential's data key, encrypted with the master key.
	// Never serialised.
	DEKWrapped []byte `json:"-"`
}

// ---------------------------------------------------------------- snippets ---

// SnippetFolder organises snippets.
type SnippetFolder struct {
	ID        string `json:"id"`
	ParentID  string `json:"parent_id"`
	Name      string `json:"name"`
	SortOrder int    `json:"sort_order"`
}

// SnippetVariable declares one placeholder in a snippet body.
type SnippetVariable struct {
	Name     string `json:"name"`
	Label    string `json:"label,omitempty"`
	Default  string `json:"default,omitempty"`
	Required bool   `json:"required,omitempty"`
	// Source names a context value that fills this automatically: host,
	// hostname, username, port, folder. Empty means prompt the user.
	Source string `json:"source,omitempty"`
}

// SnippetRunMode controls what happens when a snippet is used.
type SnippetRunMode string

const (
	// RunModeInsert puts the rendered command on the prompt for review. Default.
	RunModeInsert SnippetRunMode = "insert"
	// RunModeRun submits it immediately. Opt-in per snippet.
	RunModeRun SnippetRunMode = "run"
)

// Snippet is a reusable command.
type Snippet struct {
	ID          string            `json:"id"`
	FolderID    string            `json:"folder_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Body        string            `json:"body"`
	Shell       string            `json:"shell"`
	OSFamily    string            `json:"os_family,omitempty"`
	Variables   []SnippetVariable `json:"variables"`
	IsFavorite  bool              `json:"is_favorite"`
	Hotkey      string            `json:"hotkey,omitempty"`
	RunMode     SnippetRunMode    `json:"run_mode"`
	UseCount    int               `json:"use_count"`
	CreatedBy   string            `json:"created_by"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// ---------------------------------------------------- sessions & transfers ---

// SessionStatus is the lifecycle state recorded in history.
type SessionStatus string

const (
	SessionConnecting   SessionStatus = "connecting"
	SessionConnected    SessionStatus = "connected"
	SessionDisconnected SessionStatus = "disconnected"
	SessionFailed       SessionStatus = "failed"
	SessionClosed       SessionStatus = "closed"
)

// SessionRecord is the durable history of one session.
type SessionRecord struct {
	ID            string        `json:"id"`
	UserID        string        `json:"user_id"`
	HostID        string        `json:"host_id"`
	HostSnapshot  string        `json:"host_snapshot"`
	Protocol      Protocol      `json:"protocol"`
	Status        SessionStatus `json:"status"`
	ClientIP      string        `json:"client_ip"`
	StartedAt     time.Time     `json:"started_at"`
	EndedAt       *time.Time    `json:"ended_at,omitempty"`
	BytesIn       int64         `json:"bytes_in"`
	BytesOut      int64         `json:"bytes_out"`
	RecordingPath string        `json:"recording_path,omitempty"`
	ExitReason    string        `json:"exit_reason,omitempty"`

	// Joined for the Recent panel.
	HostName string `json:"host_name,omitempty"`
}

// TransferDirection is upload or download.
type TransferDirection string

const (
	TransferUpload   TransferDirection = "upload"
	TransferDownload TransferDirection = "download"
)

// TransferStatus is a queue entry's state.
type TransferStatus string

const (
	TransferQueued TransferStatus = "queued"
	TransferActive TransferStatus = "active"
	TransferDone   TransferStatus = "completed"
	TransferFailed TransferStatus = "failed"
	TransferCancel TransferStatus = "cancelled"
	// TransferInterrupted marks a transfer that was in flight when the backend
	// stopped. The UI offers Retry rather than showing a progress bar that will
	// never move again.
	TransferInterrupted TransferStatus = "interrupted"
)

// Terminal reports whether a status is final.
func (s TransferStatus) Terminal() bool {
	switch s {
	case TransferDone, TransferFailed, TransferCancel, TransferInterrupted:
		return true
	}
	return false
}

// Transfer is one queued or historical file transfer.
type Transfer struct {
	ID               string            `json:"id"`
	UserID           string            `json:"user_id"`
	HostID           string            `json:"host_id"`
	Direction        TransferDirection `json:"direction"`
	RemotePath       string            `json:"remote_path"`
	DisplayName      string            `json:"display_name"`
	SizeBytes        *int64            `json:"size_bytes,omitempty"`
	TransferredBytes int64             `json:"transferred_bytes"`
	Status           TransferStatus    `json:"status"`
	Error            string            `json:"error,omitempty"`
	SpeedBPS         int64             `json:"speed_bps"`
	RetryCount       int               `json:"retry_count"`
	QueuedAt         time.Time         `json:"queued_at"`
	StartedAt        *time.Time        `json:"started_at,omitempty"`
	FinishedAt       *time.Time        `json:"finished_at,omitempty"`

	HostName string `json:"host_name,omitempty"`
}

// TunnelKind selects the forwarding direction.
type TunnelKind string

const (
	TunnelLocal  TunnelKind = "local"
	TunnelRemote TunnelKind = "remote"
	TunnelSOCKS  TunnelKind = "socks"
)

// Valid reports whether the kind is one the schema accepts.
func (k TunnelKind) Valid() bool {
	switch k {
	case TunnelLocal, TunnelRemote, TunnelSOCKS:
		return true
	}
	return false
}

// Tunnel is a stored port-forward definition.
type Tunnel struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	HostID     string     `json:"host_id"`
	Kind       TunnelKind `json:"kind"`
	ListenHost string     `json:"listen_host"`
	ListenPort int        `json:"listen_port"`
	TargetHost string     `json:"target_host,omitempty"`
	TargetPort int        `json:"target_port,omitempty"`
	Autostart  bool       `json:"autostart"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// Workspace is a saved tab and split layout.
type Workspace struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Name      string    `json:"name"`
	Layout    string    `json:"layout"` // opaque JSON produced by the frontend
	IsDefault bool      `json:"is_default"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ------------------------------------------------------------ exec & audit ---

// ExecMode selects fan-out strategy.
type ExecMode string

const (
	ExecParallel   ExecMode = "parallel"
	ExecSequential ExecMode = "sequential"
)

// ExecJobStatus is a batch job's state.
type ExecJobStatus string

const (
	ExecRunning   ExecJobStatus = "running"
	ExecCompleted ExecJobStatus = "completed"
	ExecCancelled ExecJobStatus = "cancelled"
	ExecFailed    ExecJobStatus = "failed"
)

// ExecHostStatus is one host's result within a job.
type ExecHostStatus string

const (
	ExecHostPending   ExecHostStatus = "pending"
	ExecHostRunning   ExecHostStatus = "running"
	ExecHostCompleted ExecHostStatus = "completed"
	ExecHostFailed    ExecHostStatus = "failed"
	ExecHostTimeout   ExecHostStatus = "timeout"
	ExecHostCancelled ExecHostStatus = "cancelled"
	ExecHostSkipped   ExecHostStatus = "skipped"
)

// ExecJob is one multi-host command run.
type ExecJob struct {
	ID          string        `json:"id"`
	UserID      string        `json:"user_id"`
	Command     string        `json:"command"`
	Mode        ExecMode      `json:"mode"`
	Concurrency int           `json:"concurrency"`
	TimeoutS    int           `json:"timeout_s"`
	StopOnError bool          `json:"stop_on_error"`
	Status      ExecJobStatus `json:"status"`
	RiskAck     string        `json:"risk_ack,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	FinishedAt  *time.Time    `json:"finished_at,omitempty"`
	Hosts       []ExecJobHost `json:"hosts,omitempty"`
}

// ExecJobHost is one host's outcome within a job.
type ExecJobHost struct {
	JobID      string         `json:"job_id"`
	HostID     string         `json:"host_id"`
	HostLabel  string         `json:"host_label"`
	Status     ExecHostStatus `json:"status"`
	ExitCode   *int           `json:"exit_code,omitempty"`
	Stdout     string         `json:"stdout"`
	Stderr     string         `json:"stderr"`
	Truncated  bool           `json:"truncated"`
	Error      string         `json:"error,omitempty"`
	DurationMS int64          `json:"duration_ms"`
	StartedAt  *time.Time     `json:"started_at,omitempty"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
}

// AuditResult is the outcome recorded for an action.
type AuditResult string

const (
	AuditSuccess AuditResult = "success"
	AuditFailure AuditResult = "failure"
	AuditDenied  AuditResult = "denied"
)

// AuditSeverity ranks an event for filtering and alerting.
type AuditSeverity string

const (
	SeverityInfo     AuditSeverity = "info"
	SeverityNotice   AuditSeverity = "notice"
	SeverityWarning  AuditSeverity = "warning"
	SeverityCritical AuditSeverity = "critical"
)

// AuditEvent is one append-only log entry.
type AuditEvent struct {
	ID            int64          `json:"id"`
	Timestamp     time.Time      `json:"ts"`
	UserID        string         `json:"user_id,omitempty"`
	Username      string         `json:"username"`
	HostID        string         `json:"host_id,omitempty"`
	HostSnapshot  string         `json:"host_snapshot,omitempty"`
	Action        string         `json:"action"`
	Target        string         `json:"target,omitempty"`
	Result        AuditResult    `json:"result"`
	Severity      AuditSeverity  `json:"severity"`
	ClientIP      string         `json:"client_ip,omitempty"`
	AuthSessionID string         `json:"auth_session_id,omitempty"`
	Detail        map[string]any `json:"detail,omitempty"`
	RequestID     string         `json:"request_id,omitempty"`
}

// CryptoKey records a master key version so rotation is auditable and
// passphrase-derived keys can be reproduced after a restart.
type CryptoKey struct {
	Version   int        `json:"version"`
	Algo      string     `json:"algo"`
	KDF       string     `json:"kdf,omitempty"`
	KDFSalt   []byte     `json:"-"`
	KDFParams string     `json:"-"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

// Settings keys used by the application.
const (
	SettingCanary          = "crypto.canary"
	SettingInstanceName    = "instance.name"
	SettingCommandLogging  = "audit.command_logging"
	SettingDiscoveryOptIn  = "discovery.enabled"
	SettingSetupCompleted  = "setup.completed"
	SettingAIProviderURL   = "ai.provider_url"
	SettingMetricsDashURL  = "metrics.dashboard_url"
	SettingBrandingMessage = "branding.login_message"
)

// User settings keys.
const (
	UserSettingTheme         = "ui.theme"
	UserSettingTerminalTheme = "terminal.theme"
	UserSettingTerminalFont  = "terminal.font"
	UserSettingTerminalSize  = "terminal.font_size"
	UserSettingKeybindings   = "ui.keybindings"
	UserSettingSidebarWidth  = "ui.sidebar_width"
	UserSettingLayout        = "ui.layout"
)

// joinHostPort brackets IPv6 literals, so a host stored as ::1 renders as [::1]:22
// rather than an unparseable address.
func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
