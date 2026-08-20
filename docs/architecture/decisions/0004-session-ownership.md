# ADR 0004 — Sessions are owned by the backend, not the browser tab

**Status:** Accepted · **Date:** 2026-08-19

## Context

A browser tab is an unreliable container for a shell session. Users reload pages, laptops
sleep, VPNs drop, Wi-Fi roams between access points. The naive design — WebSocket closes,
session dies — means a dropped connection during `apt upgrade` or a long `rsync` loses the
work and, worse, leaves the operator unsure what completed.

## Decision

A terminal session is a backend object with its own lifecycle. A WebSocket is a *view* of
it, and attaching or detaching a view does not affect the session.

Each session owns a ring buffer (default 256 KiB, configurable) of recent output with
sequence numbers. On attach, buffered output is replayed before live output resumes; a client
that still holds part of the stream requests only the delta.

**Input is never replayed.** Keystrokes in flight when a socket dies are dropped. Nothing is
executed on the user's behalf after a reconnect.

## Reasoning

1. It is what the workflow requires: long-running operations must survive a browser reload.
2. Reconnection becomes genuinely lossless rather than a fresh shell impersonating the old
   one — which is the behaviour that leads operators to believe a command ran when it did not.
3. Terminal geometry becomes server-side state, so reattaching restores correct `cols`/`rows`
   instead of re-flowing a shell that was never resized.
4. Session recording is a tee on an existing stream rather than a browser-side hack.
5. Multiple views of one session (e.g. two panes, or a second browser) fall out naturally.

## Consequences

- Memory is held per session for the ring buffer; bounded by per-user session caps and idle
  timeouts (default: unattached sessions close after 30 minutes, audited).
- Sessions are process-affine. Multi-replica deployment therefore requires sticky routing —
  noted in ADR 0002 as an existing constraint rather than a new one.
- Graceful shutdown must notify attached clients with a reason instead of dropping sockets,
  so the UI can distinguish "server restarted" from "network died".
- Ring buffer size is a real trade-off: too small and a reload loses output, too large and
  many idle sessions cost memory. It is configurable and documented, with the default sized
  for a few screens of scrollback.
- The state machine (`connecting → connected → detached → reattached → closed/failed`) must
  be modelled explicitly on both ends, and the tab indicator must distinguish "alive but
  detached" from "dead", because a frozen pane that still accepts keystrokes is dangerous.
