package httpx

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/axt-term/axt-term/backend/internal/logging"
)

func TestRunServesThenShutsDownInOrder(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		order []string
	)
	record := func(name string) func(context.Context) error {
		return func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, name)
			return nil
		}
	}

	ready := make(chan struct{})
	srv := NewServer(ServerConfig{
		Addr:          "127.0.0.1:0",
		ShutdownGrace: 5 * time.Second,
		Ready:         ready,
	}, okHandler(), logging.Discard())

	// Registration order is the documented shutdown sequence: tell WebSocket
	// clients why they are being disconnected, then drain transfers, then close
	// sessions, then the database.
	srv.OnDraining("notify-websockets", record("notify-websockets"))
	srv.OnShutdown("drain-transfers", record("drain-transfers"))
	srv.OnShutdown("close-sessions", record("close-sessions"))
	srv.OnShutdown("close-database", record("close-database"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not begin listening")
	}

	resp, err := http.Get("http://" + srv.Addr() + "/anything")
	if err != nil {
		t.Fatalf("server should be reachable: %v", err)
	}
	_ = resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful shutdown returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not complete")
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"notify-websockets", "drain-transfers", "close-sessions", "close-database"}
	if len(order) != len(want) {
		t.Fatalf("shutdown steps = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Errorf("shutdown step %d = %q, want %q (full order %v)", i, order[i], want[i], order)
		}
	}
}

func TestShutdownReportsFailingStepWithoutAbortingTheRest(t *testing.T) {
	t.Parallel()

	var ran []string
	var mu sync.Mutex
	add := func(name string) {
		mu.Lock()
		defer mu.Unlock()
		ran = append(ran, name)
	}

	ready := make(chan struct{})
	srv := NewServer(ServerConfig{
		Addr:          "127.0.0.1:0",
		ShutdownGrace: 5 * time.Second,
		Ready:         ready,
	}, okHandler(), logging.Discard())

	wantErr := errors.New("transfer queue would not drain")
	srv.OnShutdown("drain-transfers", func(context.Context) error {
		add("drain-transfers")
		return wantErr
	})
	// A failure earlier in the sequence must not skip closing sessions: leaking
	// SSH connections is worse than a noisy shutdown.
	srv.OnShutdown("close-sessions", func(context.Context) error {
		add("close-sessions")
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	<-ready
	cancel()

	err := <-done
	if err == nil {
		t.Fatal("expected the failing step to be reported")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error should wrap the step's error, got: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(ran) != 2 {
		t.Errorf("both steps should have run, got %v", ran)
	}
}

func TestRunReturnsListenError(t *testing.T) {
	t.Parallel()

	srv := NewServer(ServerConfig{Addr: "127.0.0.1:70000"}, okHandler(), logging.Discard())
	err := srv.Run(context.Background())
	if err == nil {
		t.Fatal("expected a listen failure for an out-of-range port")
	}
}
