package sshx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// A host is not "a connection". A host has one SSH transport, and features are
// channels on it: the terminal is a PTY channel, the file browser is an SFTP
// subsystem, the System panel opens exec channels, a tunnel opens direct-tcpip
// channels. Opening the Files tab on a host that already has a terminal therefore
// costs one channel rather than a fresh authentication.
//
// Conn is reference-counted. When the last consumer releases it, an idle timer
// starts; if nothing acquires it before the timer fires, the transport closes.

// ChainResolver turns a host id into the chain needed to reach it, with
// credentials resolved. Supplied by the caller so this package does not depend on
// the inventory or credential services.
type ChainResolver func(ctx context.Context, hostID string) ([]Hop, error)

// Conn is a pooled SSH transport to one host.
type Conn struct {
	HostID string
	Label  string

	chain *Chain

	mu       sync.Mutex
	refs     int
	closed   bool
	sftp     *sftp.Client
	lastUsed time.Time
	idleFrom time.Time

	pool *Pool
}

// Client returns the underlying SSH client.
func (c *Conn) Client() *ssh.Client { return c.chain.Client }

// Banners returns any login banners the hosts presented.
func (c *Conn) Banners() []string { return c.chain.Banners }

// SFTP returns the shared SFTP client, creating it on first use.
//
// pkg/sftp is safe for concurrent use, so one subsystem serves every file
// operation on this host. Concurrent reads and writes are enabled and the
// per-file request window is raised well above the default because transfers
// frequently cross a WAN, where one outstanding request per file wastes most of
// the available bandwidth to latency.
func (c *Conn) SFTP() (*sftp.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("sshx: connection is closed")
	}
	if c.sftp != nil {
		return c.sftp, nil
	}
	client, err := sftp.NewClient(c.chain.Client,
		sftp.MaxPacket(32*1024),
		sftp.UseConcurrentReads(true),
		sftp.UseConcurrentWrites(true),
		sftp.MaxConcurrentRequestsPerFile(64),
	)
	if err != nil {
		return nil, fmt.Errorf("sshx: open sftp subsystem: %w", err)
	}
	c.sftp = client
	return client, nil
}

// Release decrements the reference count. Every Acquire must be paired with
// exactly one Release.
func (c *Conn) Release() {
	if c == nil || c.pool == nil {
		return
	}
	c.pool.release(c)
}

// Refs reports the current consumer count, for diagnostics.
func (c *Conn) Refs() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refs
}

func (c *Conn) close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	sftpClient := c.sftp
	c.sftp = nil
	c.mu.Unlock()

	var errs []error
	if sftpClient != nil {
		if err := sftpClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := c.chain.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// PoolConfig configures the connection pool.
type PoolConfig struct {
	// IdleTimeout is how long an unreferenced connection is kept before closing.
	IdleTimeout time.Duration
}

func (c PoolConfig) withDefaults() PoolConfig {
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 5 * time.Minute
	}
	return c
}

// Pool holds live SSH transports keyed by host.
type Pool struct {
	cfg      PoolConfig
	dialer   *Dialer
	resolver ChainResolver
	log      *slog.Logger

	mu      sync.Mutex
	conns   map[string]*Conn
	dialing map[string]chan struct{}
}

// NewPool creates a connection pool.
func NewPool(cfg PoolConfig, dialer *Dialer, resolver ChainResolver, log *slog.Logger) *Pool {
	return &Pool{
		cfg:      cfg.withDefaults(),
		dialer:   dialer,
		resolver: resolver,
		log:      log,
		conns:    make(map[string]*Conn),
		dialing:  make(map[string]chan struct{}),
	}
}

// Acquire returns a connection to a host, dialing if necessary.
//
// Concurrent acquisitions for the same host coalesce: the first dials while the
// others wait, so opening a terminal and the file browser at the same moment
// produces one authentication rather than two.
func (p *Pool) Acquire(ctx context.Context, hostID string) (*Conn, error) {
	for {
		p.mu.Lock()
		if conn, ok := p.conns[hostID]; ok {
			conn.mu.Lock()
			if !conn.closed {
				conn.refs++
				conn.lastUsed = time.Now()
				conn.idleFrom = time.Time{}
				conn.mu.Unlock()
				p.mu.Unlock()
				return conn, nil
			}
			conn.mu.Unlock()
			// The cached connection is closing; drop it and dial fresh.
			delete(p.conns, hostID)
		}

		if wait, inFlight := p.dialing[hostID]; inFlight {
			p.mu.Unlock()
			select {
			case <-wait:
				continue // the winner published a connection; look again
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		done := make(chan struct{})
		p.dialing[hostID] = done
		p.mu.Unlock()

		conn, err := p.dial(ctx, hostID)

		p.mu.Lock()
		delete(p.dialing, hostID)
		if err == nil {
			p.conns[hostID] = conn
		}
		close(done)
		p.mu.Unlock()

		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}

func (p *Pool) dial(ctx context.Context, hostID string) (*Conn, error) {
	hops, err := p.resolver(ctx, hostID)
	if err != nil {
		return nil, err
	}
	if len(hops) == 0 {
		return nil, fmt.Errorf("sshx: no connection chain resolved for host %s", hostID)
	}
	// The plaintext secrets in the chain are needed only for the handshake.
	defer zeroAuth(hops)

	chain, err := p.dialer.Dial(ctx, hops)
	if err != nil {
		return nil, err
	}

	target := hops[len(hops)-1]
	conn := &Conn{
		HostID:   hostID,
		Label:    target.Label,
		chain:    chain,
		refs:     1,
		lastUsed: time.Now(),
		pool:     p,
	}

	// When the transport dies for any reason -- remote reboot, network drop,
	// sshd restart -- remove it from the pool so the next acquire dials fresh
	// instead of handing out a dead client.
	go func() {
		_ = chain.Client.Wait()
		p.mu.Lock()
		if current, ok := p.conns[hostID]; ok && current == conn {
			delete(p.conns, hostID)
		}
		p.mu.Unlock()
		_ = conn.close()
		p.log.Debug("ssh transport closed",
			slog.String("host_id", hostID), slog.String("label", conn.Label))
	}()

	return conn, nil
}

func (p *Pool) release(c *Conn) {
	c.mu.Lock()
	if c.refs > 0 {
		c.refs--
	}
	if c.refs == 0 {
		c.idleFrom = time.Now()
	}
	c.mu.Unlock()
}

// Sweep closes connections that have been idle beyond the configured timeout.
func (p *Pool) Sweep() int {
	cutoff := time.Now().Add(-p.cfg.IdleTimeout)

	p.mu.Lock()
	var stale []*Conn
	for hostID, conn := range p.conns {
		conn.mu.Lock()
		idle := conn.refs == 0 && !conn.idleFrom.IsZero() && conn.idleFrom.Before(cutoff)
		conn.mu.Unlock()
		if idle {
			stale = append(stale, conn)
			delete(p.conns, hostID)
		}
	}
	p.mu.Unlock()

	for _, conn := range stale {
		if err := conn.close(); err != nil {
			p.log.Debug("error closing idle connection",
				slog.String("host_id", conn.HostID), slog.Any("error", err))
		}
		p.log.Debug("closed idle ssh transport",
			slog.String("host_id", conn.HostID), slog.String("label", conn.Label))
	}
	return len(stale)
}

// CloseHost drops the connection to one host, regardless of references.
//
// Used when a host's credentials or address change: continuing to serve a
// connection built from stale configuration would be surprising and wrong.
func (p *Pool) CloseHost(hostID string) {
	p.mu.Lock()
	conn, ok := p.conns[hostID]
	if ok {
		delete(p.conns, hostID)
	}
	p.mu.Unlock()
	if ok {
		_ = conn.close()
	}
}

// CloseAll closes every connection. Called during shutdown.
func (p *Pool) CloseAll() {
	p.mu.Lock()
	conns := make([]*Conn, 0, len(p.conns))
	for _, c := range p.conns {
		conns = append(conns, c)
	}
	p.conns = make(map[string]*Conn)
	p.mu.Unlock()

	for _, c := range conns {
		_ = c.close()
	}
}

// Stats reports pool contents, for the metrics endpoint.
func (p *Pool) Stats() (connections, references int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		connections++
		references += c.Refs()
	}
	return connections, references
}

// StartSweeper runs Sweep periodically until ctx is cancelled.
func (p *Pool) StartSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.Sweep()
		}
	}
}

// zeroAuth wipes the secrets in a resolved chain once dialing is finished.
//
// Best-effort, for the reasons crypto.Zero documents, but it removes the copy
// that would otherwise sit in a core dump or a swapped page.
func zeroAuth(hops []Hop) {
	for i := range hops {
		for _, b := range [][]byte{
			hops[i].Auth.Password,
			hops[i].Auth.PrivateKey,
			hops[i].Auth.Passphrase,
		} {
			for j := range b {
				b[j] = 0
			}
		}
	}
}
