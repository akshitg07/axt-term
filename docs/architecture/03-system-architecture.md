# 3. System Architecture

## 3.1 Runtime topology

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│ BROWSER                                                                          │
│  React SPA ── xterm.js · Monaco · guacamole-common-js                            │
│    │                                                                             │
│    ├── HTTPS  /api/v1/*   session cookie + CSRF header                           │
│    └── WSS    /ws/*       single-use ticket + Origin validation                   │
└────┬─────────────────────────────────────────────────────────────────────────────┘
     │  TLS 1.3
┌────▼─────────────────────────────────────────────────────────────────────────────┐
│ caddy — TLS termination, HSTS, security headers, WS upgrade passthrough           │
└────┬─────────────────────────────────────────────────────────────────────────────┘
     │  HTTP/1.1 on internal network
┌────▼─────────────────────────────────────────────────────────────────────────────┐
│ AXT-TERM BACKEND  (single Go process)                                            │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │ HTTP layer:  recover → request-id → logging → rate-limit → authn →         │  │
│  │              CSRF → authz(RBAC) → audit → handler                          │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐   │
│  │ Session      │  │ Host         │  │ Transfer     │  │ Tunnel             │   │
│  │ Registry     │  │ Connection   │  │ Workers      │  │ Listeners          │   │
│  │              │  │ Pool         │  │              │  │                    │   │
│  │ id → session │  │ host → conn  │  │ N goroutines │  │ net.Listener each  │   │
│  │ ring buffers │  │ refcounted   │  │ DB-backed q  │  │                    │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └─────────┬──────────┘   │
│         │                 │                 │                    │              │
│  ┌──────▼─────────────────▼─────────────────▼────────────────────▼───────────┐  │
│  │ Protocol engines:   ssh  ·  sftp  ·  guacd client  ·  exec  ·  sysinfo    │  │
│  └───────────────────────────────┬───────────────────────────────────────────┘  │
│                                  │                                              │
│  ┌───────────────┐  ┌────────────▼─────────┐  ┌──────────────┐  ┌────────────┐  │
│  │ Credentials   │  │ Store (SQLite/WAL)   │  │ Audit        │  │ Event bus  │  │
│  │ envelope AES  │  │ 1 writer + read pool │  │ append-only  │  │ in-process │  │
│  └───────┬───────┘  └──────────────────────┘  └──────────────┘  └────────────┘  │
│          │                                                                       │
│    ┌─────▼──────┐  master key from env/keyfile, never in DB                      │
│    │  KEK       │                                                                │
│    └────────────┘                                                                │
└────┬───────────────────────────────────────────────┬─────────────────────────────┘
     │ SSH 22 / SFTP subsystem                       │ Guacamole protocol (internal)
     │                                          ┌────▼──────┐
     │                                          │  guacd    │
     │                                          └────┬──────┘
     │                                               │ RDP 3389 / VNC 5900
┌────▼───────────────────────────────────────────────▼─────────────────────────────┐
│ TARGET INFRASTRUCTURE                                                            │
│  Linux hosts · bastions · Windows hosts · switches/routers · Docker · K8s API    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## 3.2 Process model

One Go process. Concurrency is structured, not ad hoc — every long-lived goroutine has an
owner, a `context.Context` for cancellation, and a place it reports failures to.

| Goroutine set | Count | Lifetime | Owner |
| --- | --- | --- | --- |
| HTTP handlers | per request | request | `net/http` |
| Session pump (SSH stdout → ring buffer → attached WS) | 1 per live session | session | Session Registry |
| Session stdin pump (WS → SSH stdin) | 1 per attached WS | attachment | WS handler |
| Host connection keepalive | 1 per host connection | connection | Connection Pool |
| Transfer workers | `AXT_TRANSFER_WORKERS` (default 4) | process | Transfer service |
| Tunnel accept loops | 1 per active tunnel + 1 per forwarded conn | tunnel | Tunnel service |
| Health checker | 1 | process | Inventory |
| guacd relays | 2 per RDP session | session | RDP bridge |

Shutdown is ordered and graceful: stop accepting HTTP → notify WS clients with a close
reason → drain transfers (mark in-flight rows `interrupted`, resumable) → close sessions →
close tunnels → checkpoint WAL → exit. `SIGTERM` gets `AXT_SHUTDOWN_GRACE` (default 20s).

## 3.3 SSH architecture

### Dialing and jump chains

Jump hosts are the composition of `ssh.Client.Dial` — a client on the bastion produces a
`net.Conn` to the next hop, which becomes the transport for the next client. This is
exactly what OpenSSH's `ProxyJump` does, and the UI presents it as picking a host from a
dropdown, never as SSH config syntax.

```
resolveChain(host) → [bastion, target]        (cycle-detected, depth-limited to 5)

  net.Dial("tcp", bastion)          ──▶ ssh.NewClientConn ──▶ client₀
  client₀.Dial("tcp", target)       ──▶ ssh.NewClientConn ──▶ client₁   ← the session client
```

Each hop authenticates with its own credential and is host-key-verified independently.
A failure names the hop that failed, because "connection refused" without knowing which
link broke is a waste of the engineer's time.

### Host key verification

Not optional and not skippable by default. `ssh.HostKeyCallback` is backed by a
`host_keys` table:

| Situation | Behaviour |
| --- | --- |
| No key recorded | Trust-on-first-use: connection pauses, UI shows the SHA256 fingerprint and key type, user accepts or rejects. `AXT_SSH_HOSTKEY_POLICY=strict` rejects instead. |
| Key matches | Proceed, update `last_seen_at`. |
| Key mismatch | **Hard fail.** Audit event `ssh.hostkey.mismatch` at warning level, both fingerprints shown, no override in the connect path. Clearing requires an explicit administrative action on the host-keys screen. |

### Authentication methods

Tried in the order the credential specifies, never blind-cycled: `publickey`
(with optional encrypted passphrase), `password`, `keyboard-interactive` (for hosts that
present password auth that way), and SSH agent via `SSH_AUTH_SOCK` when the operator
has mounted one into the container.

### PTY sessions

`RequestPty` with the terminal type, initial `cols`/`rows`, and modes including
`ECHO=1`, `ICRNL`, `ISIG`. `WindowChange` is sent on resize, debounced to 50 ms so a
mouse-drag of a split divider does not flood the channel.

### Ring buffer and replay

Each session owns a lock-free-enough ring buffer (mutex + byte slice; the contention
window is nanoseconds). Default 256 KiB, configurable per deployment. On attach the
buffer is written to the socket first, followed by live output — with a sequence number
so a reattaching client that still holds part of the stream can ask for only the delta
rather than re-rendering everything.

## 3.4 SFTP architecture

One SFTP subsystem client per host connection, created lazily and shared. `pkg/sftp` is
safe for concurrent use, and requests are pipelined with `MaxConcurrentRequestsPerFile`
tuned for WAN latency.

| Operation | Implementation notes |
| --- | --- |
| List | `ReadDir` + `Lstat` for symlink targets; resolved server-side so the UI can show link destinations |
| Download | Streamed straight to the HTTP response with `Content-Disposition`; HTTP `Range` supported so browser-native resume works |
| Upload | Streamed from the request body; **never buffered fully in memory** |
| Editor read | Size-capped (`AXT_EDITOR_MAX_BYTES`, default 8 MiB) with charset sniffing and binary rejection |
| Editor save | Atomic: write `.axt-tmp-<rand>` beside the target, `fsync`, `Chmod` to the original mode, `Rename` over it. Optional pre-write backup to `<name>.bak-<timestamp>` |
| Path safety | Every path is cleaned, must be absolute, and is rejected if it escapes the configured root or contains a null byte. §06 covers traversal defence in full |

Atomic-rename-over is what prevents the classic disaster: a dropped connection halfway
through saving `nginx.conf` leaving a truncated file that fails to start on reload.

## 3.5 WebSocket architecture

Three endpoints, one authentication model:

| Endpoint | Payload |
| --- | --- |
| `/ws/terminal` | Terminal I/O for one session |
| `/ws/rdp` | Guacamole instruction stream for one session |
| `/ws/events` | Per-user notifications: transfer progress, health changes, job output, session state |

### Framing

Binary frames carry data with a one-byte opcode; text frames carry JSON control messages.
Keystrokes must not pay for JSON encoding, and terminal output must not pay for base64.

```
BINARY   [0x00] <bytes>     server → client   stdout/stderr
         [0x01] <bytes>     client → server   stdin
         [0x02] <bytes>     server → client   replay from ring buffer (attach only)

TEXT     {"t":"resize","cols":120,"rows":34}          client → server
         {"t":"status","state":"connected","seq":91}  server → client
         {"t":"error","code":"host_unreachable","message":"..."}
         {"t":"exit","code":0,"reason":"remote closed"}
         {"t":"ping"} / {"t":"pong"}
```

### Lifecycle and reconnection

```
client                                            server
  │ POST /sessions {host_id,protocol,cols,rows}      │
  │◀─────────── {session_id, state:"connecting"} ────│  SSH dial starts immediately
  │ POST /sessions/{id}/ticket                       │
  │◀─────────── {ticket, expires_in: 30} ────────────│  single-use, bound to user+session+IP
  │ WS  /ws/terminal?ticket=…   Origin: https://…    │
  │──────────────────────────────────────────────────▶  ticket consumed atomically
  │◀── [0x02] replay ─── {"t":"status","connected"} ──│
  │◀══════════ [0x00] output   /   [0x01] input ═════▶│
  │                                                   │
  │  ✗ network drops                                  │  session survives; buffer accumulates
  │  exponential backoff 0.5s → 8s, jitter, 6 tries   │
  │ POST /sessions/{id}/ticket  → WS re-attach        │
  │◀── [0x02] delta since seq ── {"status":"restored"}│  input never replayed
```

Application-level ping every 30 s with a 10 s pong deadline detects half-open connections
that TCP will not report for minutes — the difference between a terminal that says
"Reconnecting…" in two seconds and one that appears to work but is dead.

## 3.6 RDP bridge

```
browser (guacamole-common-js)          backend                       guacd            Windows
   │  WS /ws/rdp?ticket=                 │                             │                 │
   │────────────────────────────────────▶│ validate ticket, load host  │                 │
   │                                     │ decrypt credentials         │                 │
   │                                     │──── select/size/audio ─────▶│                 │
   │                                     │◀─── args ───────────────────│                 │
   │                                     │──── connect(hostname,       │                 │
   │                                     │      port, user, password,  │                 │
   │                                     │      domain, security) ────▶│──── RDP/NLA ───▶│
   │◀═══ instruction stream ═════════════│◀════ instructions ══════════│◀════ desktop ═══│
   │═══▶ key/mouse/clipboard ═══════════▶│═════════════════════════════▶                 │
```

The backend is a full Guacamole protocol participant: it parses the length-prefixed
`opcode,arg,arg;` instruction format, injects credentials during the handshake, and then
relays. Credentials appear only in the backend→guacd hop on a private network.

Instructions from guacd are relayed to the browser essentially untouched, except that the
backend enforces size limits and drops `file`/`pipe` streams unless drive redirection is
enabled for that host.

## 3.7 Multi-host execution (Command Center)

```
POST /exec/batch {host_ids[], command, mode: parallel|sequential,
                  concurrency, timeout_s, stop_on_error, confirm_token}
   │
   ├─ job row persisted, job_id returned immediately
   ├─ semaphore-bounded fan-out (default concurrency 8)
   ├─ per host: acquire/create connection → exec channel (no PTY) → capture
   │            stdout/stderr with a per-host output cap
   └─ progress streamed over /ws/events; results persisted per host
```

Non-interactive `exec` channels, not PTYs — the output is for aggregation, not
rendering, and no TTY means no pager surprises. Every host result carries exit status,
duration, and truncation flag. Cancellation closes channels and marks remaining hosts
`cancelled`, and a job that is cancelled mid-flight reports honestly which hosts already
ran the command. §06 covers the confirmation gate for destructive patterns.

## 3.8 Tunnels

| Kind | Mechanism |
| --- | --- |
| Local forward | `net.Listen` on the backend, each accepted conn → `client.Dial(target)`, bidirectional copy |
| Remote forward | `client.Listen(remote addr)` on the target, each accepted conn → local dial |
| SOCKS5 | Local SOCKS5 server; `CONNECT` requests dialled through the SSH client |

A tunnel is only bound to `0.0.0.0` if the operator explicitly opts in
(`AXT_TUNNEL_ALLOW_PUBLIC_BIND`); the default bind is `127.0.0.1`, because a tunnel that
silently exposes an internal database to the LAN is a security incident, not a feature.

## 3.9 System information without an agent

`sysinfo` runs a small set of read-only commands over an existing SSH connection and
parses them, with per-command timeouts and graceful degradation — a missing field is shown
as unknown rather than failing the panel.

| Fact | Source, in preference order |
| --- | --- |
| Distro / version | `/etc/os-release` |
| Kernel | `uname -sr` |
| CPU model / cores | `/proc/cpuinfo`, `nproc` |
| Load, uptime | `/proc/loadavg`, `/proc/uptime` |
| Memory | `/proc/meminfo` |
| Disk | `df -PT` |
| CPU utilisation | two `/proc/stat` samples ~500 ms apart |
| Network interfaces | `ip -j addr` with a `/proc/net/dev` fallback |
| Processes | `ps -eo pid,ppid,user,pcpu,pmem,rss,etimes,comm,args` |
| Services | `systemctl list-units --type=service --all --output=json` |

Reading `/proc` and using `-j`/`--output=json` where available avoids fragile
column-position parsing. Nothing is installed on the target, and results are cached
briefly so an open System panel does not re-shell every second.
