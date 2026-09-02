package rdp

import (
	"testing"

	"github.com/axt-term/axt-term/backend/internal/credentials"
	"github.com/axt-term/axt-term/backend/internal/store"
)

func rdpHost(mutate func(*store.Host)) *store.Host {
	host := &store.Host{
		ID:       "host-1",
		Name:     "win-dc01",
		Hostname: "10.0.4.11",
		Port:     3389,
		Protocol: store.ProtocolRDP,
	}
	if mutate != nil {
		mutate(host)
	}
	return host
}

func passwordCredential() *credentials.Resolved {
	return &credentials.Resolved{
		Kind:     store.CredRDPPassword,
		Username: "administrator",
		Domain:   "CORP",
		Password: []byte("hunter2"),
	}
}

func TestRDPParamsCarryIdentity(t *testing.T) {
	host := rdpHost(nil)
	p := BuildParams(host, passwordCredential(), Display{Width: 1280, Height: 800, DPI: 96})

	expect := map[string]string{
		"hostname": "10.0.4.11",
		"port":     "3389",
		"username": "administrator",
		"password": "hunter2",
		"domain":   "CORP",
		"width":    "1280",
		"height":   "800",
		"dpi":      "96",
	}
	for key, want := range expect {
		if p[key] != want {
			t.Errorf("param %q = %q, want %q", key, p[key], want)
		}
	}
}

func TestRDPParamsHostOverridesCredential(t *testing.T) {
	// The host form says its username overrides the credential's, and its domain is
	// specific to this machine while the credential is shared across many.
	host := rdpHost(func(h *store.Host) {
		h.Username = "svc-deploy"
		h.RDPOptions.Domain = "DMZ"
	})

	p := BuildParams(host, passwordCredential(), Display{Width: 1024, Height: 768})

	if p["username"] != "svc-deploy" {
		t.Errorf("username = %q, want the host's", p["username"])
	}
	if p["domain"] != "DMZ" {
		t.Errorf("domain = %q, want the host's", p["domain"])
	}
	if p["password"] != "hunter2" {
		t.Errorf("password should still come from the credential, got %q", p["password"])
	}
}

func TestRDPParamsWithoutCredential(t *testing.T) {
	// A host with no credential must still produce a usable parameter set rather
	// than panicking on a nil.
	p := BuildParams(rdpHost(nil), nil, Display{Width: 1024, Height: 768})

	if p["hostname"] != "10.0.4.11" {
		t.Errorf("hostname = %q", p["hostname"])
	}
	if p["password"] != "" || p["username"] != "" {
		t.Errorf("expected no identity, got username=%q password=%q", p["username"], p["password"])
	}
}

// TestRDPClipboardIsOptIn covers a security default. guacd expresses the clipboard
// as two negatives, and both directions are gated together.
func TestRDPClipboardIsOptIn(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		p := BuildParams(rdpHost(nil), nil, Display{Width: 1024, Height: 768})
		if p["disable-copy"] != "true" || p["disable-paste"] != "true" {
			t.Errorf("clipboard should be disabled by default, got copy=%q paste=%q",
				p["disable-copy"], p["disable-paste"])
		}
	})

	t.Run("enabled per host", func(t *testing.T) {
		host := rdpHost(func(h *store.Host) { h.RDPOptions.EnableClipboard = true })
		p := BuildParams(host, nil, Display{Width: 1024, Height: 768})
		if p["disable-copy"] != "false" || p["disable-paste"] != "false" {
			t.Errorf("clipboard should be enabled, got copy=%q paste=%q",
				p["disable-copy"], p["disable-paste"])
		}
	})
}

func TestRDPDriveRedirectionIsOptIn(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		p := BuildParams(rdpHost(nil), nil, Display{Width: 1024, Height: 768})
		if p["enable-drive"] != "" {
			t.Errorf("drive redirection should be absent, got %q", p["enable-drive"])
		}
	})

	t.Run("enabled with a path", func(t *testing.T) {
		host := rdpHost(func(h *store.Host) {
			h.RDPOptions.EnableDrive = true
			h.RDPOptions.DrivePath = "/var/lib/axt-term/drive"
		})
		p := BuildParams(host, nil, Display{Width: 1024, Height: 768})

		if p["enable-drive"] != "true" {
			t.Errorf("enable-drive = %q", p["enable-drive"])
		}
		if p["drive-path"] != "/var/lib/axt-term/drive" {
			t.Errorf("drive-path = %q", p["drive-path"])
		}
		// Without this guacd fails the connection when the directory is missing,
		// which is a confusing way to learn about a typo.
		if p["create-drive-path"] != "true" {
			t.Errorf("create-drive-path = %q", p["create-drive-path"])
		}
	})
}

func TestRDPAudioAndWallpaper(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		p := BuildParams(rdpHost(nil), nil, Display{Width: 1024, Height: 768})
		if p["disable-audio"] != "true" {
			t.Errorf("audio should be off by default, got disable-audio=%q", p["disable-audio"])
		}
		// DisableWallpaper is stored as a negative, so the default shows wallpaper.
		if p["enable-wallpaper"] != "true" {
			t.Errorf("enable-wallpaper = %q, want true by default", p["enable-wallpaper"])
		}
	})

	t.Run("audio on and wallpaper suppressed", func(t *testing.T) {
		host := rdpHost(func(h *store.Host) {
			h.RDPOptions.EnableAudio = true
			h.RDPOptions.DisableWallpaper = true
		})
		p := BuildParams(host, nil, Display{Width: 1024, Height: 768})

		if p["disable-audio"] != "false" {
			t.Errorf("disable-audio = %q, want false", p["disable-audio"])
		}
		if p["enable-wallpaper"] != "" {
			t.Errorf("enable-wallpaper = %q, want absent", p["enable-wallpaper"])
		}
	})
}

func TestRDPResizeMethodDefaultsToDisplayUpdate(t *testing.T) {
	// display-update resizes without dropping the session; the alternative
	// reconnects, which loses the desktop for a moment.
	p := BuildParams(rdpHost(nil), nil, Display{Width: 1024, Height: 768})
	if p["resize-method"] != "display-update" {
		t.Errorf("resize-method = %q, want display-update", p["resize-method"])
	}

	host := rdpHost(func(h *store.Host) { h.RDPOptions.ResizeMethod = "reconnect" })
	p = BuildParams(host, nil, Display{Width: 1024, Height: 768})
	if p["resize-method"] != "reconnect" {
		t.Errorf("resize-method = %q, want the host's choice", p["resize-method"])
	}
}

func TestRDPOmitsUnsetOptionalParameters(t *testing.T) {
	// An empty value means "use guacd's default" only for parameters guacd asked
	// about; sending our own empty strings for things the user never set clutters
	// the connect payload and can override a default with nothing.
	p := BuildParams(rdpHost(nil), nil, Display{Width: 1024, Height: 768})

	for _, key := range []string{
		"security", "ignore-cert", "color-depth", "remote-app",
		"preconnection-blob", "console", "server-layout", "timezone",
		"enable-theming", "enable-font-smoothing", "enable-printing",
	} {
		if _, present := p[key]; present {
			t.Errorf("param %q should be absent when unset, got %q", key, p[key])
		}
	}
}

func TestVNCParams(t *testing.T) {
	host := &store.Host{
		ID:       "host-2",
		Name:     "kiosk",
		Hostname: "10.0.9.3",
		Port:     5900,
		Protocol: store.ProtocolVNC,
		RDPOptions: store.RDPOptions{
			SwapRedBlue:       true,
			Cursor:            "remote",
			ReadOnly:          true,
			ClipboardEncoding: "UTF-8",
			ColorDepth:        24,
			EnableClipboard:   true,
		},
	}
	cred := &credentials.Resolved{Kind: store.CredPassword, Password: []byte("vncsecret")}

	p := BuildParams(host, cred, Display{Width: 1440, Height: 900, DPI: 96})

	expect := map[string]string{
		"hostname":           "10.0.9.3",
		"port":               "5900",
		"password":           "vncsecret",
		"swap-red-blue":      "true",
		"cursor":             "remote",
		"read-only":          "true",
		"clipboard-encoding": "UTF-8",
		"color-depth":        "24",
		"disable-copy":       "false",
	}
	for key, want := range expect {
		if p[key] != want {
			t.Errorf("param %q = %q, want %q", key, p[key], want)
		}
	}

	// VNC authenticates with a password alone; sending a username is meaningless
	// and some servers reject the connection outright.
	if _, present := p["username"]; present {
		t.Errorf("VNC params should carry no username, got %q", p["username"])
	}
	// RDP-only parameters must not leak into a VNC connect.
	for _, key := range []string{"domain", "security", "resize-method", "enable-drive"} {
		if _, present := p[key]; present {
			t.Errorf("VNC params should not carry %q", key)
		}
	}
}

func TestGuacProtocol(t *testing.T) {
	if got := GuacProtocol(store.ProtocolVNC); got != "vnc" {
		t.Errorf("GuacProtocol(vnc) = %q", got)
	}
	if got := GuacProtocol(store.ProtocolRDP); got != "rdp" {
		t.Errorf("GuacProtocol(rdp) = %q", got)
	}
}

func TestDisplayForFallsBackToHostPreference(t *testing.T) {
	host := rdpHost(func(h *store.Host) {
		h.RDPOptions.InitialWidth = 1600
		h.RDPOptions.InitialHeight = 1200
	})

	t.Run("client geometry wins", func(t *testing.T) {
		got := DisplayFor(host, Display{Width: 1280, Height: 720, DPI: 96})
		if got.Width != 1280 || got.Height != 720 {
			t.Errorf("got %dx%d, want the client's 1280x720", got.Width, got.Height)
		}
	})

	t.Run("host preference when the client sends none", func(t *testing.T) {
		got := DisplayFor(host, Display{})
		if got.Width != 1600 || got.Height != 1200 {
			t.Errorf("got %dx%d, want the host's 1600x1200", got.Width, got.Height)
		}
		if got.DPI != 96 {
			t.Errorf("DPI = %d, want a sane default", got.DPI)
		}
	})

	t.Run("defaults when neither is set", func(t *testing.T) {
		got := DisplayFor(rdpHost(nil), Display{})
		if got.Width < 640 || got.Height < 480 {
			t.Errorf("got an unusable default display %dx%d", got.Width, got.Height)
		}
	})
}
