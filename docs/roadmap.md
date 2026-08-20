# Development Roadmap

## Principles

- **Every milestone is shippable and testable.** No milestone ends with a UI that is wired to
  nothing, or a backend feature with no way to exercise it.
- **Vertical before horizontal.** Prove one path end-to-end (log in → connect → real shell)
  before broadening. That path exercises auth, crypto, SSH, WebSockets, and the shell UI
  together — the integration risk is where the risk actually is.
- **Coming Soon is explicit.** Unimplemented panels render a labelled placeholder that says
  what it will do and which phase it lands in. No dead buttons.

---

# Phase 1 — MVP

**Goal:** a self-hosted deployment where an engineer logs in, adds hosts and credentials,
opens a real interactive SSH session, browses and transfers files over SFTP, edits a remote
file, uses snippets, and returns to a preserved workspace after a reload.

## M1 — Foundation

Repository scaffold; `Makefile` targets (`dev`, `build`, `test`, `lint`, `types`, `migrate`);
config loader with validation and a redacted startup dump; `slog` logging with request ids
and a secret-scrubbing handler; `/healthz`, `/readyz`, `/version`; graceful shutdown;
golangci-lint and CI.

*Done when:* `make dev` serves `/healthz`, CI is green, and startup fails loudly on bad config.
*Tests:* config parsing and validation, log scrubbing, shutdown ordering.

## M2 — Store, migrations, crypto

Embedded migration runner with checksum verification; schema through `0008`; SQLite store
with a single writer and a read pool; envelope encryption (`crypto`) with startup canary
validation; `axt-admin user create` and `axt-admin key rotate`.

*Done when:* a fresh volume migrates cleanly, `axt-admin user create` produces a login-capable
user, and rotating the master key preserves every secret.
*Tests:* migration idempotency and checksum-mismatch abort; encrypt/decrypt round trip; AAD
mismatch rejection; tamper detection; wrong-key rejection; rotation correctness.

## M3 — Authentication and authorization

Argon2id passwords; login/logout/me; cookie sessions with sliding and absolute expiry; CSRF
double-submit; origin validation; security headers; rate limiting and account lockout; the
permission registry with route declarations that fail startup when missing.

*Done when:* the authz matrix test passes for every route × role and no route lacks a
declaration.
*Tests:* login success/failure/lockout; timing parity for unknown users; CSRF rejection on
every mutating route; cookie attributes; session expiry and revocation; authz matrix.

## M4 — Inventory and credentials API

Folders (nested, move, delete strategies), hosts (CRUD, search, filter, favourite,
duplicate, `ssh_config` import, export without secrets), tags, credentials (CRUD, metadata-only
reads, usage listing), `/hosts/{id}/actions`.

*Done when:* an inventory of 500 hosts imported from `ssh_config` lists in under 50 ms and no
response contains a secret.
*Tests:* CRUD and validation; folder cycle prevention; jump-host cycle prevention; a
serialisation test asserting known secret values never appear in any response; `ssh_config`
parsing.

## M5 — SSH engine

Dialer with jump chains (depth limit, cycle detection, per-hop errors); host-key TOFU store
with hard-fail on mismatch; the refcounted `HostConnection` pool with keepalive and idle
close; PTY sessions with resize; non-interactive exec with output caps; `POST /hosts/{id}/test`.

*Done when:* integration tests connect to a containerised sshd directly and through a
bastion, run a command, and verify host-key behaviour.
*Tests (integration, real sshd):* password and key auth; wrong credential; unreachable host;
jump chain; host-key accept/match/mismatch; connection reuse across consumers; idle close.

## M6 — Terminal sessions and WebSocket transport

Session registry; ring buffer with sequence numbers; `/ws/terminal` with ticket auth and
framing; attach/detach/replay; resize; ping/pong half-open detection; session records and
audit events; per-user session caps.

*Done when:* a scripted client attaches, runs a long command, disconnects mid-output,
reattaches, and receives the missed output exactly once — with no input replay.
*Tests:* ticket validity (expired, reused, wrong user, wrong session, wrong origin, wrong
IP); attach/detach/replay correctness; ring-buffer wraparound; resize propagation; half-open
detection; concurrent attachment behaviour.

## M7 — Frontend foundation

Design tokens and four themes; `components/ui` primitives; the shell (top bar, sidebar, tab
strip, session area, drawer, status bar) with persisted layout; the command registry with
palette and keybindings; typed API client with CSRF handling; reconnecting WS client; login
screen; toasts.

*Done when:* the shell is fully keyboard-navigable, themes switch without flash, and layout
survives a reload.
*Tests:* component tests for primitives; keybinding conflict detection; API client CSRF and
error mapping; fuzzy matcher scoring.

## M8 — Terminal UI end to end

xterm.js with fit/webgl/search/web-links/unicode11/serialize; the framing codec; the host
tree with health dots and inline actions; quick connect (`Ctrl+K`); tabs with real state
semantics; terminal toolbar (copy, paste, search, clear, settings, fullscreen); host-key
trust prompt; reconnect UI with backoff; frozen-pane input blocking.

*Done when:* `Ctrl+K` → three characters → `Enter` gives a working shell in under a second on
a LAN host, and pulling the network shows honest state and recovers.
*Tests:* codec round trip; reconnect state machine; disabled input when frozen; e2e
(Playwright) login → connect → `echo` → assert output.

## M9 — SFTP and file manager

Directory ops with full path safety; streamed download with `Range`; streamed upload; atomic
editor write with `expected_mtime`; chmod/chown; recursive delete behind the confirmation
gate; the durable transfer queue with workers, progress over `/ws/events`, retry, cancel, and
restart recovery; single-pane and dual-pane UI with virtualisation, multi-select, drag and
drop, and the transfers drawer.

*Done when:* a 1 GB upload and download complete with accurate progress and ETA, a mid-transfer
cancel leaves no partial queue state, and a backend restart marks in-flight transfers
retryable.
*Tests:* the path-traversal table on every endpoint; atomic write preserving mode; mtime
conflict returning 409; large-file streaming without backend memory growth; queue
persistence across restart; retry and cancel; confirmation-token binding and replay rejection.

## M10 — Editor, snippets, recent, search, settings

Monaco bundled locally with detected languages and pre-save backup for sensitive paths;
snippet CRUD with folders, variables, server-side rendering, insert-by-default and hotkeys;
recent sessions; unified `/search`; settings for appearance, terminal, keybindings, and
account.

*Done when:* editing and saving `/etc/nginx/nginx.conf` works with a backup written, and a
snippet with `{service}` inserts a resolved command into the focused terminal without running
it.
*Tests:* language detection; conflict flow; variable rendering including missing-variable
errors; snippet import/export round trip; search relevance.

## M11 — Deployment, documentation, hardening

Multi-stage `Dockerfile` (node → go → distroless, non-root, embedded SPA); `docker-compose.yml`
with Caddy and volumes and healthchecks; `.env.example`; backup and restore scripts and
documentation; upgrade documentation; installation, configuration, security, SSH, SFTP, and
troubleshooting guides; `docs/configuration.md` generated from config struct tags.

*Done when:* on a clean machine, `cp .env.example .env && docker compose up -d` yields a
working HTTPS instance, and the documented backup/restore cycle reproduces state exactly.
*Tests:* container smoke test in CI (compose up, migrate, login, connect to the test sshd,
transfer a file, tear down).

### Phase 1 explicitly excludes

RDP, splits, Command Center, broadcast, tunnels, processes, services, Docker, Kubernetes,
workspaces, discovery, the connection graph, and the audit UI. Audit *events are recorded*
from M3 onward — only the browsing UI waits for Phase 3. Every excluded panel ships as a
labelled Coming Soon placeholder naming its phase.

---

# Phase 2 — Multi-host and remote desktop

| Milestone | Contents |
| --- | --- |
| M12 | Terminal splits: recursive pane tree, directional focus, zoom, per-pane status |
| M13 | RDP: guacd client, instruction codec, `/ws/rdp`, `guacamole-common-js` canvas, clipboard, resize, reconnect |
| M14 | Command Center: job model, bounded fan-out, timeouts, cancellation, retry-failed, output grouping and export |
| M15 | Broadcast mode with the full warning treatment and auto-disable rules |
| M16 | SSH tunnels: local, remote, SOCKS5; lifecycle UI; localhost-bind default |
| M17 | Jump-host UI: visual chain builder, per-hop diagnostics |
| M18 | Process manager and service manager, with confirmation on signals and stops |
| M19 | Session recording (asciicast v2), playback, download; TOTP two-factor |

# Phase 3 — Platform integrations

| Milestone | Contents |
| --- | --- |
| M20 | Docker manager: containers, images, volumes, networks, logs, stats, exec into a terminal tab |
| M21 | Kubernetes: kubeconfig storage (encrypted), resource browsing, logs, exec, describe, YAML, port-forward, with read-only and destructive operations visually separated |
| M22 | Workspaces: save, restore, default; layout serialisation |
| M23 | Audit UI: search, filters, export; retention tooling |
| M24 | Host discovery: opt-in CIDR scan, banner-only fingerprinting, import |
| M25 | Connection graph via React Flow with per-node action menus |
| M26 | Smart terminal features: URL/IP/path/error detection with contextual actions |
| M27 | Log viewer with follow, filter, and highlight |

# Phase 4 — Extensibility

| Milestone | Contents |
| --- | --- |
| M28 | Plugin architecture: manifest, host providers, resource providers, contextual actions, UI panel slots, capability-scoped permissions |
| M29 | Tailscale plugin (device discovery → host import, tags as folders) |
| M30 | Proxmox and XCP-ng plugins (VM inventory, console, power actions) |
| M31 | Prometheus/Grafana metrics panel; embedded dashboard links |
| M32 | Ansible/AWX plugin; Git integration for config directories |
| M33 | Optional local AI layer: provider interface, Ollama/llama.cpp adapters, explain-error and summarise-logs actions — off by default, never phoning home |
| M34 | Advanced RBAC: host-scoped permissions, approval workflows, SSO/OIDC |
| M35 | PostgreSQL store implementation and multi-replica deployment with session affinity |

---

## Definition of done, for every milestone

1. Feature works against real infrastructure, not a mock.
2. Unit tests for logic; integration tests for anything crossing a protocol boundary.
3. Errors surface actionable messages — which host, which hop, which path.
4. Security review against §06 for any new input, route, or credential path.
5. Audit events for anything administratively interesting.
6. Documentation updated in the same change.
7. No secret reachable by the frontend; no unprotected route; no dead UI control.
