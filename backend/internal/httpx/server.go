package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// ServerConfig configures the HTTP server.
type ServerConfig struct {
	Addr          string
	ShutdownGrace time.Duration
	// ReadHeaderTimeout bounds how long a client may take to send headers.
	ReadHeaderTimeout time.Duration
	// IdleTimeout bounds keep-alive connections between requests.
	IdleTimeout time.Duration
	// Ready, when non-nil, is closed once the listener is bound. Tests wait on
	// it instead of racing startup or polling a fixed port.
	Ready chan<- struct{}
}

func (c ServerConfig) withDefaults() ServerConfig {
	if c.ShutdownGrace <= 0 {
		c.ShutdownGrace = 20 * time.Second
	}
	if c.ReadHeaderTimeout <= 0 {
		c.ReadHeaderTimeout = 10 * time.Second
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 120 * time.Second
	}
	return c
}

// Server wraps http.Server with ordered graceful shutdown.
type Server struct {
	cfg  ServerConfig
	log  *slog.Logger
	srv  *http.Server
	addr string

	draining []hook // run before the listener drains, e.g. notify WebSocket clients
	closing  []hook // run after HTTP has drained, in registration order
}

type hook struct {
	name string
	fn   func(context.Context) error
}

// NewServer builds a server around a handler.
//
// Note the absence of ReadTimeout and WriteTimeout. Both apply to the whole
// connection, which would terminate every WebSocket session and every large
// file transfer on a fixed schedule. Per-request bounds come from the Timeout
// middleware, which is applied to ordinary API routes and skipped for streaming
// ones.
func NewServer(cfg ServerConfig, handler http.Handler, log *slog.Logger) *Server {
	cfg = cfg.withDefaults()
	return &Server{
		cfg: cfg,
		log: log,
		srv: &http.Server{
			Addr:              cfg.Addr,
			Handler:           handler,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			IdleTimeout:       cfg.IdleTimeout,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		},
	}
}

// OnDraining registers work to run as shutdown begins, before in-flight HTTP
// requests are awaited.
//
// This is where WebSocket clients are told why they are being disconnected.
// http.Server.Shutdown does not track hijacked connections, so a session that is
// not closed here would simply vanish, and the browser could not distinguish a
// planned restart from a network failure.
func (s *Server) OnDraining(name string, fn func(context.Context) error) {
	s.draining = append(s.draining, hook{name: name, fn: fn})
}

// OnShutdown registers work to run after HTTP has drained. Hooks run in
// registration order, which is the documented shutdown sequence: drain
// transfers, close sessions, close tunnels, checkpoint the database.
func (s *Server) OnShutdown(name string, fn func(context.Context) error) {
	s.closing = append(s.closing, hook{name: name, fn: fn})
}

// Addr returns the bound address, which is only known after Run has begun
// listening. Useful in tests that bind port 0.
func (s *Server) Addr() string { return s.addr }

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.Addr, err)
	}
	s.addr = ln.Addr().String()

	served := make(chan error, 1)
	go func() {
		err := s.srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		served <- err
	}()

	s.log.Info("http server listening", slog.String("addr", s.addr))
	if s.cfg.Ready != nil {
		close(s.cfg.Ready)
	}

	select {
	case err := <-served:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	return s.shutdown(served)
}

func (s *Server) shutdown(served <-chan error) error {
	s.log.Info("shutting down", slog.Duration("grace", s.cfg.ShutdownGrace))

	// One deadline covers the whole sequence so a slow phase cannot let the
	// total exceed the operator's configured grace period.
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownGrace)
	defer cancel()

	var errs []error

	for _, h := range s.draining {
		s.runHook(ctx, h, &errs)
	}

	if err := s.srv.Shutdown(ctx); err != nil {
		s.log.Warn("http shutdown did not complete cleanly", slog.Any("error", err))
		errs = append(errs, fmt.Errorf("http shutdown: %w", err))
	}

	for _, h := range s.closing {
		s.runHook(ctx, h, &errs)
	}

	if err := <-served; err != nil {
		errs = append(errs, fmt.Errorf("serve: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	s.log.Info("shutdown complete")
	return nil
}

func (s *Server) runHook(ctx context.Context, h hook, errs *[]error) {
	start := time.Now()
	if err := h.fn(ctx); err != nil {
		s.log.Warn("shutdown step failed",
			slog.String("step", h.name),
			slog.Any("error", err),
			slog.Duration("duration", time.Since(start).Round(time.Millisecond)),
		)
		*errs = append(*errs, fmt.Errorf("%s: %w", h.name, err))
		return
	}
	s.log.Debug("shutdown step complete",
		slog.String("step", h.name),
		slog.Duration("duration", time.Since(start).Round(time.Millisecond)),
	)
}
