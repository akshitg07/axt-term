package sshx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Auth carries resolved credentials for one hop.
//
// Secrets are []byte rather than string so they can be zeroed after use; see
// crypto.Zero for why that is best-effort but still worth doing.
type Auth struct {
	Username    string
	Password    []byte
	PrivateKey  []byte
	Passphrase  []byte
	UseAgent    bool
	AgentSocket string
}

// Hop is one link in a connection chain.
type Hop struct {
	HostID   string
	Label    string // human-readable, used in error messages
	Hostname string
	Port     int
	Auth     Auth
}

// Address renders the hop's dial target.
func (h Hop) Address() string { return net.JoinHostPort(h.Hostname, strconv.Itoa(h.Port)) }

// DialConfig configures the dialer.
type DialConfig struct {
	ConnectTimeout    time.Duration
	KeepaliveInterval time.Duration
	HostKeyPolicy     string
	LegacyAlgorithms  bool
	MaxHops           int
	// ClientVersion is sent in the SSH identification string.
	ClientVersion string
}

func (c DialConfig) withDefaults() DialConfig {
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = 15 * time.Second
	}
	if c.KeepaliveInterval <= 0 {
		c.KeepaliveInterval = 30 * time.Second
	}
	if c.MaxHops <= 0 {
		c.MaxHops = 5
	}
	if c.ClientVersion == "" {
		c.ClientVersion = "SSH-2.0-AXT-Term"
	}
	return c
}

// Dialer establishes SSH connections, composing jump-host chains.
type Dialer struct {
	cfg      DialConfig
	verifier *Verifier
	log      *slog.Logger
}

// NewDialer creates a dialer.
func NewDialer(cfg DialConfig, verifier *Verifier, log *slog.Logger) *Dialer {
	return &Dialer{cfg: cfg.withDefaults(), verifier: verifier, log: log}
}

// HopError names which link in a chain failed.
//
// "connection refused" without knowing which hop refused is a waste of the
// engineer's time, and with a three-hop chain it is genuinely ambiguous.
type HopError struct {
	Index int
	Total int
	Label string
	Addr  string
	Err   error
}

func (e *HopError) Error() string {
	if e.Total > 1 {
		return fmt.Sprintf("hop %d of %d (%s at %s): %v", e.Index+1, e.Total, e.Label, e.Addr, e.Err)
	}
	return fmt.Sprintf("%s at %s: %v", e.Label, e.Addr, e.Err)
}

func (e *HopError) Unwrap() error { return e.Err }

// Chain is an established connection, including the intermediate clients that
// must be closed with it.
type Chain struct {
	// Client is the connection to the final target.
	Client *ssh.Client
	// intermediates are bastion clients, outermost first.
	intermediates []*ssh.Client
	// rawConn is the TCP connection to the first hop.
	rawConn net.Conn
	// Banners collected from each hop, in order.
	Banners []string
}

// Close tears the chain down from the target back towards the first bastion.
func (c *Chain) Close() error {
	var errs []error
	if c.Client != nil {
		if err := c.Client.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for i := len(c.intermediates) - 1; i >= 0; i-- {
		if err := c.intermediates[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.rawConn != nil {
		_ = c.rawConn.Close()
	}
	return errors.Join(errs...)
}

// Dial establishes a connection along the chain. The last hop is the target.
//
// A jump chain is composition: each client's Dial produces a net.Conn to the next
// hop, which becomes the transport for the next SSH handshake. That is exactly
// what OpenSSH's ProxyJump does, and every hop is authenticated and host-key
// verified independently.
func (d *Dialer) Dial(ctx context.Context, hops []Hop) (*Chain, error) {
	if len(hops) == 0 {
		return nil, errors.New("sshx: no hops supplied")
	}
	if len(hops)-1 > d.cfg.MaxHops {
		return nil, fmt.Errorf("sshx: chain of %d jump hosts exceeds the limit of %d",
			len(hops)-1, d.cfg.MaxHops)
	}

	chain := &Chain{}
	success := false
	defer func() {
		if !success {
			_ = chain.Close()
		}
	}()

	for i, hop := range hops {
		isTarget := i == len(hops)-1

		var (
			conn net.Conn
			err  error
		)
		if i == 0 {
			dialer := &net.Dialer{Timeout: d.cfg.ConnectTimeout}
			conn, err = dialer.DialContext(ctx, "tcp", hop.Address())
			if err == nil {
				chain.rawConn = conn
			}
		} else {
			// Dialling through the previous hop. x/crypto/ssh has no
			// context-aware Dial, so the deadline is applied to the resulting
			// connection instead of the dial itself.
			conn, err = chain.Client.Dial("tcp", hop.Address())
		}
		if err != nil {
			return nil, &HopError{Index: i, Total: len(hops), Label: hop.Label, Addr: hop.Address(), Err: err}
		}

		var banner string
		clientCfg, cfgErr := d.clientConfig(ctx, hop, &banner)
		if cfgErr != nil {
			_ = conn.Close()
			return nil, &HopError{Index: i, Total: len(hops), Label: hop.Label, Addr: hop.Address(), Err: cfgErr}
		}

		// Bound the handshake. Without a deadline a host that accepts TCP and
		// then goes silent hangs the session forever.
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		} else {
			_ = conn.SetDeadline(time.Now().Add(d.cfg.ConnectTimeout))
		}

		sshConn, chans, reqs, hErr := ssh.NewClientConn(conn, hop.Address(), clientCfg)
		if hErr != nil {
			_ = conn.Close()
			return nil, &HopError{Index: i, Total: len(hops), Label: hop.Label, Addr: hop.Address(), Err: hErr}
		}
		// Clear the handshake deadline; the session that follows is long-lived.
		_ = conn.SetDeadline(time.Time{})

		client := ssh.NewClient(sshConn, chans, reqs)

		// Every previous client becomes an intermediate that must outlive this
		// hop's handshake and be closed with the chain. Dropping the reference
		// here would leak the bastion connection.
		if chain.Client != nil {
			chain.intermediates = append(chain.intermediates, chain.Client)
		}
		chain.Client = client
		if banner != "" {
			chain.Banners = append(chain.Banners, banner)
		}

		d.log.DebugContext(ctx, "ssh hop established",
			slog.Int("hop", i+1),
			slog.Int("of", len(hops)),
			slog.String("label", hop.Label),
			slog.String("addr", hop.Address()),
			slog.Bool("target", isTarget))
	}

	success = true
	go d.keepalive(chain.Client, d.cfg.KeepaliveInterval)
	return chain, nil
}

// clientConfig builds the per-hop SSH configuration.
func (d *Dialer) clientConfig(ctx context.Context, hop Hop, banner *string) (*ssh.ClientConfig, error) {
	methods, err := authMethods(hop.Auth)
	if err != nil {
		return nil, err
	}
	if len(methods) == 0 {
		return nil, errors.New("no authentication method available: attach a credential, enable the agent, or supply a password")
	}

	cfg := &ssh.ClientConfig{
		User:            hop.Auth.Username,
		Auth:            methods,
		HostKeyCallback: d.verifier.Callback(ctx, hop.Hostname, hop.Port),
		Timeout:         d.cfg.ConnectTimeout,
		ClientVersion:   d.cfg.ClientVersion,
		BannerCallback: func(message string) error {
			*banner = message
			return nil
		},
	}

	if d.cfg.LegacyAlgorithms {
		applyLegacyAlgorithms(cfg)
	}
	return cfg, nil
}

// applyLegacyAlgorithms widens the algorithm set for network equipment that
// offers nothing modern.
//
// Opt-in per instance, and hosts relying on it are badged in the UI. Switches and
// firewalls with decade-old firmware are a real part of the estate this tool is
// for, and refusing to connect to them would just push the engineer back to
// another client.
func applyLegacyAlgorithms(cfg *ssh.ClientConfig) {
	cfg.Config.KeyExchanges = append(cfg.Config.KeyExchanges,
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
	)
	cfg.Config.Ciphers = append(cfg.Config.Ciphers,
		"aes128-cbc",
		"aes192-cbc",
		"aes256-cbc",
		"3des-cbc",
	)
	cfg.Config.MACs = append(cfg.Config.MACs,
		"hmac-sha1",
		"hmac-sha1-96",
	)
	cfg.HostKeyAlgorithms = append(cfg.HostKeyAlgorithms,
		ssh.KeyAlgoRSA,
		ssh.KeyAlgoDSA,
	)
}

// authMethods builds the authentication methods for a hop, in the order they
// should be attempted.
func authMethods(a Auth) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if len(a.PrivateKey) > 0 {
		signer, err := parsePrivateKey(a.PrivateKey, a.Passphrase)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if a.UseAgent && a.AgentSocket != "" {
		// Agent errors are not fatal: a missing socket should fall through to
		// other methods rather than failing the connection outright.
		if signers, err := agentSigners(a.AgentSocket); err == nil && len(signers) > 0 {
			methods = append(methods, ssh.PublicKeys(signers...))
		}
	}

	if len(a.Password) > 0 {
		password := string(a.Password)
		methods = append(methods, ssh.Password(password))
		// Some servers offer password auth only as keyboard-interactive. Without
		// this, those hosts appear to reject a correct password.
		methods = append(methods, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = password
				}
				return answers, nil
			}))
	}

	return methods, nil
}

func parsePrivateKey(pem, passphrase []byte) (ssh.Signer, error) {
	if len(passphrase) > 0 {
		signer, err := ssh.ParsePrivateKeyWithPassphrase(pem, passphrase)
		if err != nil {
			return nil, fmt.Errorf("private key could not be decrypted: check the passphrase (%w)", err)
		}
		return signer, nil
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("this private key is encrypted but no passphrase is stored with the credential")
		}
		return nil, fmt.Errorf("private key could not be parsed: %w", err)
	}
	return signer, nil
}

func agentSigners(socket string) ([]ssh.Signer, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("ssh agent at %s: %w", socket, err)
	}
	// The connection is intentionally not closed here: signers hold a reference
	// to it for the lifetime of the authentication attempt. It is reclaimed when
	// the process exits, and agent use is rare enough that this is acceptable.
	return agent.NewClient(conn).Signers()
}

// keepalive sends periodic global requests.
//
// Long-lived sessions otherwise die silently behind NAT devices and stateful
// firewalls that expire idle flows, and the user discovers it only when a
// keystroke goes nowhere.
func (d *Dialer) keepalive(client *ssh.Client, interval time.Duration) {
	if client == nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	closed := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(closed)
	}()

	for {
		select {
		case <-closed:
			return
		case <-ticker.C:
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				return
			}
		}
	}
}

// PublicKeyFingerprint returns the SHA-256 fingerprint of a private key's public
// half, for display on the credential screen.
func PublicKeyFingerprint(privateKey, passphrase []byte) (keyType, fingerprint, comment string, err error) {
	signer, err := parsePrivateKey(privateKey, passphrase)
	if err != nil {
		return "", "", "", err
	}
	pub := signer.PublicKey()
	return pub.Type(), ssh.FingerprintSHA256(pub), "", nil
}
