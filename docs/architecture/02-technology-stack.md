# 2. Technology Stack

Every choice below is justified against the product's actual constraints: hundreds of
concurrent long-lived streams, real SSH/SFTP throughput, air-gapped operation, and
self-hosting by one person on one box.

## 2.1 Backend language — Go vs Node/TypeScript

This decision cascades into everything, so it gets the most scrutiny.

| Criterion | Go | Node.js / TypeScript |
| --- | --- | --- |
| **SSH library maturity** | `golang.org/x/crypto/ssh` — maintained by the Go team; the transport under Docker, Kubernetes, Teleport, HashiCorp tooling. Direct control over `Dial`, per-client `Dial` for jump chains, `Listen` for remote forwards, `RequestSubsystem`. | `ssh2` — capable and widely used, but effectively single-maintainer, and the API abstracts away transport details that jump chains and forwards need. |
| **SFTP** | `pkg/sftp` — SFTP v3, concurrent request pipelining, `io.ReaderFrom`/`WriterTo` fast paths. Saturates a gigabit link. | `ssh2-sftp-client` / `ssh2` streams. Throughput bound by JS buffer copies and event-loop scheduling; measurably slower on large transfers. |
| **Concurrency model** | Goroutine per stream. 500 live PTYs ≈ tens of MB and no scheduling cliff. Blocking I/O per session is the natural style. | Single-threaded event loop. Fine for I/O-bound work, but 500 streams means 500 sets of stream callbacks competing with HTTP handling; one CPU-bound handler stalls every session. |
| **Backpressure** | `io.Copy` + explicit channel/window control; natural. | Requires disciplined `pause()`/`resume()` plumbing across every hop; easy to get subtly wrong. |
| **Memory at rest** | ~30–60 MB | ~120–200 MB before any sessions |
| **Container** | Single static binary; distroless image ~25 MB | Needs Node runtime + `node_modules`; ~150–250 MB |
| **Docker / Kubernetes clients** | Official `docker/docker` and `k8s.io/client-go` | `@kubernetes/client-node` official; `dockerode` community |
| **guacd protocol relay** | Trivial: TCP + length-prefixed instructions | Equally trivial |
| **Crypto performance** | Native, constant-time primitives; Argon2id and AES-GCM at full speed | Via libuv threadpool; acceptable but slower |
| **Type sharing with the frontend** | ✗ Needs codegen | ✓ Native — the one real advantage |
| **Operational debuggability** | `pprof`, goroutine dumps, race detector | Inspector, heap snapshots |

**Decision: Go 1.23+.**

The deciding factors are SSH/SFTP library quality and the concurrency model. AXT-Term is,
at its core, a multiplexer for hundreds of long-lived byte streams with strict latency
requirements on keystroke echo — precisely what goroutines and `x/crypto/ssh` are good at.
Node's real advantage is type sharing, and that is recoverable with tooling; Go's
advantages are not recoverable in Node.

**Mitigating the type-sharing gap:** Go structs with `json` tags are the single source of
truth for the wire format. [`tygo`](https://github.com/gzuidhof/tygo) generates
`frontend/src/types/api.gen.ts` from them, the generated file is committed, and CI fails
if it is stale (`make types && git diff --exit-code`). The frontend never hand-writes a
response type.

Recorded as [ADR 0001](decisions/0001-backend-language.md).

### Rejected alternatives

- **Rust** — best-in-class performance and `russh` is decent, but the SSH/SFTP ecosystem
  is thinner than Go's, and no reason here justifies the development-velocity cost.
- **Python** — `paramiko` is mature but slow, and the GIL plus async story makes hundreds
  of streams awkward.
- **Java** (as Guacamole itself uses) — excellent RDP story via the reference client, but
  a JVM per deployment and heavyweight framework baggage contradict the "one small
  self-hosted binary" goal. We use guacd (the C daemon) directly instead.

## 2.2 Frontend

**React 19 + TypeScript (strict) + Vite + Tailwind CSS v4.**

React because xterm.js, Monaco, and React Flow all have first-class React integration and
the component model fits a panel-heavy workspace. Vite for a sub-second dev loop and a
clean fully-offline production bundle. Tailwind because the design system here is dense,
token-driven, and theme-switchable — exactly what utility classes plus CSS custom
properties do well — with no runtime CSS-in-JS cost on a UI that must not drop frames
while a terminal is streaming.

| Concern | Choice | Why this one |
| --- | --- | --- |
| Terminal | `@xterm/xterm` + `-addon-fit`, `-addon-web-links`, `-addon-search`, `-addon-webgl`, `-addon-unicode11`, `-addon-serialize` | The only serious browser terminal. WebGL renderer keeps 60 fps under heavy output; `serialize` supports snapshot/restore and recording |
| Code editor | `monaco-editor`, bundled locally with explicit workers | Same engine as VS Code; **must not** use the CDN-loading wrapper — air-gapped is a requirement |
| Server state | TanStack Query | Cache, invalidation, and request dedup for host/file/process lists |
| Client state | Zustand | Tab tree, split layout, focus, palette state. Small, no boilerplate, no context re-render storms |
| Accessible primitives | Radix UI (headless) | Dialogs, menus, popovers, tooltips with correct focus/ARIA. Headless means our own visual identity, no borrowed design |
| Icons | Lucide | MIT, consistent 1.5px stroke, no brand assets |
| Long lists | TanStack Virtual | Directory with 20k files, `ps` with 800 rows, host tree with 500 nodes |
| Resizable layout | `react-resizable-panels` for the shell; a bespoke recursive pane tree for terminal splits | The shell needs persisted sizes; terminal splits need arbitrary nesting the library does not model |
| Graph (Phase 3) | `@xyflow/react` | MIT, handles hundreds of nodes, custom node rendering |
| RDP client | `guacamole-common-js` | Apache-2.0, the canonical client for the guacd protocol |
| Forms | React Hook Form + Zod | Zod schemas also validate WS control frames |
| Tests | Vitest + Testing Library; Playwright for e2e | |

**No** component kit that ships its own visual language (MUI, Chakra, Ant). The workspace
needs to look like professional infrastructure tooling, and that means owning the
design system.

## 2.3 Database — SQLite vs PostgreSQL

What actually goes in the database: hosts, folders, tags, credentials (encrypted),
snippets, users, workspaces, transfer queue rows, audit events. This is *configuration and
history*, not session data. Realistic scale for the target user is thousands of rows and a
handful of writes per minute, with audit events as the only meaningful write stream.

| Criterion | SQLite | PostgreSQL |
| --- | --- | --- |
| Operational burden | None. A file. | A container, a user, a password, tuning, upgrades |
| Backup | `VACUUM INTO` while running; copy one file | `pg_dump`, or PITR setup |
| Read latency | In-process, ~µs | Network round trip |
| Write concurrency | One writer at a time (WAL allows concurrent readers) | Genuine concurrent writers |
| Multi-replica backend | ✗ | ✓ |
| Fits "no unnecessary infrastructure" | ✓ | ✗ for single-node |

**Decision: SQLite by default** — `modernc.org/sqlite` (pure Go, so no CGO and a truly
static binary), with `WAL`, `foreign_keys=ON`, `busy_timeout=5000`, `synchronous=NORMAL`.
A single writer connection and a read pool avoids `SQLITE_BUSY` entirely.

**Postgres stays reachable:** all data access goes through interfaces in
`internal/store`, SQL is kept portable (no SQLite-only syntax outside the sqlite package),
and migrations are plain `.sql`. Adding `internal/store/postgres` is a contained change,
scheduled for Phase 4 when multi-replica HA is the actual requirement. The honest triggers
to switch: more than one backend replica, or audit write volume above a few hundred
events/second.

Recorded as [ADR 0002](decisions/0002-database.md).

## 2.4 No Redis, no message broker

Everything Redis would be used for has a better local answer at this scale:

| Would-be use | What we do instead |
| --- | --- |
| Session store | `auth_sessions` table + small in-memory cache; sessions are already server-affine because live PTYs are |
| Transfer queue | `transfers` table + in-process worker pool; survives restart, and history is a product feature anyway |
| Pub/sub for progress events | In-process `events` bus; all WS clients are connected to this process |
| Rate limiting | In-process token buckets keyed by user/IP |

A broker would add a container, a failure mode, and no capability. If multi-replica
arrives in Phase 4, session affinity is required regardless (PTYs are pinned to a
process), so the coordination problem is not the one Redis solves.
Recorded as [ADR 0005](decisions/0005-no-redis.md).

## 2.5 RDP — guacd sidecar

Browsers cannot speak RDP, so something must translate. Options:

| Option | Assessment |
| --- | --- |
| **guacd** (Apache Guacamole proxy daemon, Apache-2.0) | Mature C implementation of RDP/VNC/SSH/Telnet with a simple text protocol designed for exactly this relay. Handles NLA/CredSSP, clipboard, drive redirection, multi-monitor, printing, audio. Also delivers VNC and Telnet nearly free — two of the listed "future protocols". |
| Native Go RDP client | Existing libraries are incomplete: partial NLA, no reliable RemoteFX/clipboard/audio. Would be a multi-month project competing with a solved problem. |
| FreeRDP + custom WebSocket shim | Essentially rebuilding guacd, worse. |
| xrdp/VNC on the target | Requires installing software on every Windows host. Non-starter. |

**Decision: guacd as a sidecar container on an internal Docker network, never published.**
AXT-Term's Go backend is the Guacamole *client* — it opens the TCP connection to guacd,
performs the handshake with server-side-decrypted credentials, and relays instructions to
the browser over an authenticated WebSocket.

The critical property: **the browser never sees RDP credentials.** It holds only a
single-use session ticket. This is a real improvement over the common deployment pattern
where connection parameters are assembled client-side.
Recorded as [ADR 0003](decisions/0003-rdp-gateway.md).

## 2.6 Deployment and serving

The built SPA is embedded in the Go binary via `embed.FS` and served with correct
cache headers and a SPA fallback. One binary, one container, no CORS, no separate web
server to configure, no version skew between frontend and backend.

`docker compose` ships:

| Service | Role | Exposed |
| --- | --- | --- |
| `axt-term` | Go backend + embedded SPA | via proxy only |
| `guacd` | RDP/VNC translation | internal network only |
| `caddy` | TLS termination (local CA or provided certs), HSTS, security headers | 443 |

Caddy sits in an optional compose profile: it is the recommended path because AXT-Term
sets `Secure` cookies and browsers require HTTPS for them outside `localhost`, but an
operator with existing ingress can run the backend alone.

SQLite database, session recordings, and host keys live on a single named volume, so
backup is one directory plus one `VACUUM INTO`.

## 2.7 Dependency policy

Every dependency must justify itself against maintenance risk. The full backend
dependency set for Phase 1 is intentionally small:

```
golang.org/x/crypto        ssh, argon2, ed25519           (Go team)
github.com/pkg/sftp        SFTP client                    (mature, stable API)
github.com/coder/websocket WebSocket                      (minimal, context-aware, no fork history baggage)
modernc.org/sqlite         pure-Go SQLite driver
github.com/google/uuid     identifiers
```

Routing uses `net/http`'s method-and-pattern mux from Go 1.22 — no third-party router.
Logging uses `log/slog` from the standard library. Configuration is environment variables
parsed by hand-written code, roughly 100 lines, rather than a configuration framework.

Rejected: ORMs (hand-written SQL is clearer for 20 tables and audit-friendly), web
frameworks (stdlib is sufficient), dependency-injection containers (explicit constructor
wiring in `main.go` is the whole graph and stays readable).
