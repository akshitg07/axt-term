package rdp

import (
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/axt-term/axt-term/backend/internal/credentials"
	"github.com/axt-term/axt-term/backend/internal/store"
)

// Params is a guacd connection parameter set.
//
// It holds the decrypted password for a Windows host, and the whole security
// argument for making the backend the Guacamole client (ADR 0003) is that this
// value exists only here and on the wire to guacd.
//
// "Don't log it" is not enough of a guarantee: Go's fmt prints a bare map's
// contents for %v, so a single well-meant debug line would spill every
// credential. Params therefore implements Stringer and slog.LogValuer, both
// redacting, which makes the safe thing the default one -- there is no formatting
// verb that reveals a value.
type Params map[string]string

// String redacts. See the type comment.
func (p Params) String() string {
	return fmt.Sprintf("guacd params (%d keys, redacted)", len(p))
}

// LogValue redacts for structured logging.
//
// Key *names* are safe and genuinely useful when diagnosing a handshake, so they
// are listed; no value ever is.
func (p Params) LogValue() slog.Value {
	names := make([]string, 0, len(p))
	for name := range p {
		names = append(names, name)
	}
	sort.Strings(names)
	return slog.GroupValue(
		slog.Int("count", len(p)),
		slog.String("keys", strings.Join(names, ",")),
	)
}

// boolParam renders a guacd boolean. guacd accepts "true"/"false" and treats an
// empty value as unset, which is not the same as false: an explicit "false" can
// override a default that is on.
func boolParam(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// BuildParams assembles the connection parameters for a host.
//
// cred may be nil, for a VNC server with no password or an RDP host relying on
// pass-through. The host's own Username overrides the credential's, matching the
// hint the host form already shows and the way the SSH dialer resolves it.
func BuildParams(host *store.Host, cred *credentials.Resolved, display Display) Params {
	switch host.Protocol {
	case store.ProtocolVNC:
		return vncParams(host, cred, display)
	default:
		return rdpParams(host, cred, display)
	}
}

// resolveIdentity picks the username, password, and domain actually used.
func resolveIdentity(host *store.Host, cred *credentials.Resolved) (username, password, domain string) {
	if cred != nil {
		username = cred.Username
		password = string(cred.Password)
		domain = cred.Domain
	}
	if host.Username != "" {
		username = host.Username
	}
	// The host's RDP options win over the credential's domain: the credential is
	// shared across hosts, the host setting is specific to this one.
	if host.RDPOptions.Domain != "" {
		domain = host.RDPOptions.Domain
	}
	return username, password, domain
}

func rdpParams(host *store.Host, cred *credentials.Resolved, display Display) Params {
	opts := host.RDPOptions
	username, password, domain := resolveIdentity(host, cred)

	p := Params{
		"hostname": host.Hostname,
		"port":     strconv.Itoa(host.Port),
		"username": username,
		"password": password,
		"domain":   domain,

		"width":  strconv.Itoa(display.Width),
		"height": strconv.Itoa(display.Height),
		"dpi":    strconv.Itoa(display.DPI),

		// Clipboard is opt-in per host, and guacd expresses it as two negatives.
		// Both directions are gated together: a one-way clipboard is a surprising
		// thing to explain to somebody wondering why paste works and copy does not.
		"disable-copy":  boolParam(!opts.EnableClipboard),
		"disable-paste": boolParam(!opts.EnableClipboard),
	}

	// security empty means guacd negotiates. Only send a value the user chose.
	if opts.Security != "" {
		p["security"] = opts.Security
	}
	if opts.IgnoreCert {
		p["ignore-cert"] = "true"
	}
	if opts.ColorDepth > 0 {
		p["color-depth"] = strconv.Itoa(opts.ColorDepth)
	}
	if opts.ResizeMethod != "" {
		p["resize-method"] = opts.ResizeMethod
	} else {
		// display-update is the modern path and resizes without dropping the
		// session; guacd falls back on its own if the server cannot do it.
		p["resize-method"] = "display-update"
	}

	// Visual features are opt-in in guacd, which defaults them off for bandwidth.
	// DisableWallpaper is stored as a negative, so it inverts here.
	if !opts.DisableWallpaper {
		p["enable-wallpaper"] = "true"
	}
	if opts.EnableTheming {
		p["enable-theming"] = "true"
	}
	if opts.EnableFontSmoothing {
		p["enable-font-smoothing"] = "true"
	}

	// Audio is a stream we advertised in the handshake; disable-audio suppresses it.
	p["disable-audio"] = boolParam(!opts.EnableAudio)

	if opts.EnableDrive {
		p["enable-drive"] = "true"
		p["drive-name"] = "AXT-Term"
		if opts.DrivePath != "" {
			p["drive-path"] = opts.DrivePath
			// Without this guacd fails the connection when the directory is
			// missing, which is a confusing way to learn about a typo.
			p["create-drive-path"] = "true"
		}
	}
	if opts.EnablePrinting {
		p["enable-printing"] = "true"
		p["printer-name"] = "AXT-Term"
	}

	if opts.RemoteApp != "" {
		p["remote-app"] = opts.RemoteApp
	}
	if opts.PreconnectionBlob != "" {
		p["preconnection-blob"] = opts.PreconnectionBlob
	}
	if opts.Console {
		p["console"] = "true"
	}
	if opts.ServerLayout != "" {
		p["server-layout"] = opts.ServerLayout
	}
	if opts.Timezone != "" {
		p["timezone"] = opts.Timezone
	}

	return p
}

func vncParams(host *store.Host, cred *credentials.Resolved, display Display) Params {
	opts := host.RDPOptions

	password := ""
	if cred != nil {
		password = string(cred.Password)
	}

	p := Params{
		"hostname": host.Hostname,
		"port":     strconv.Itoa(host.Port),
		"password": password,

		// VNC has no display-update equivalent, so the initial size is what the
		// server gives us and the browser scales. Sent anyway for servers that
		// honour it.
		"width":  strconv.Itoa(display.Width),
		"height": strconv.Itoa(display.Height),
		"dpi":    strconv.Itoa(display.DPI),

		"disable-copy":  boolParam(!opts.EnableClipboard),
		"disable-paste": boolParam(!opts.EnableClipboard),
	}

	if opts.ColorDepth > 0 {
		p["color-depth"] = strconv.Itoa(opts.ColorDepth)
	}
	if opts.SwapRedBlue {
		p["swap-red-blue"] = "true"
	}
	if opts.ReadOnly {
		p["read-only"] = "true"
	}
	if opts.Cursor != "" {
		p["cursor"] = opts.Cursor
	}
	if opts.ClipboardEncoding != "" {
		p["clipboard-encoding"] = opts.ClipboardEncoding
	}
	// VNC servers commonly are not listening the instant a VM boots; a couple of
	// retries turns a race into a connection.
	p["autoretry"] = "3"

	return p
}

// GuacProtocol returns the guacd protocol name for a host.
func GuacProtocol(protocol store.Protocol) string {
	if protocol == store.ProtocolVNC {
		return "vnc"
	}
	return "rdp"
}

// DisplayFor resolves the display geometry for a host, preferring what the client
// asked for and falling back to the host's saved preference.
func DisplayFor(host *store.Host, requested Display) Display {
	if requested.Width <= 0 && host.RDPOptions.InitialWidth > 0 {
		requested.Width = host.RDPOptions.InitialWidth
	}
	if requested.Height <= 0 && host.RDPOptions.InitialHeight > 0 {
		requested.Height = host.RDPOptions.InitialHeight
	}
	return requested.withDefaults()
}
