# 1. Product Architecture

## 1.1 What AXT-Term is

A self-hosted server that an infrastructure engineer points a browser at, and from that
one tab reaches every machine they administer — Linux over SSH, Windows over RDP, files
over SFTP, containers, clusters — without switching applications.

Concretely it is three things:

1. **An inventory** of hosts, folders, tags, credentials, and snippets.
2. **A protocol gateway** that holds live SSH/SFTP/RDP connections on the server side and
   projects them into the browser.
3. **A workspace shell** that arranges those projections into tabs, splits, and panels.

The gateway is the hard part and the reason this is a server application rather than a
browser extension: browsers cannot speak SSH, and putting credentials in a browser to
try would be the wrong design even if they could.

## 1.2 The workflow the product optimises

```
 Find host ──▶ Connect ──▶ Work ──▶ Transfer ──▶ Inspect ──▶ Manage ──▶ Automate ──▶ Next host
   ⌃K          Enter       PTY      Files tab    System      Services   Command       ⌃K
                                                  Logs       Docker     Center
```

Every arrow above must cost at most one keystroke or one click. That single constraint
drives most of the UX architecture: the command palette, the fuzzy host search, the
per-host contextual action set, and the fact that opening the Files tab for a host reuses
the SSH connection already established for its terminal instead of authenticating again.

### The design question we keep asking

> An engineer runs 50 Linux servers, 10 Windows servers, 3 Kubernetes clusters, 2 NAS
> boxes, several Docker hosts, switches, routers, VPN nodes and a monitoring stack.
> What makes *that* engineer faster today than yesterday?

Answers that shaped the product, and where they live:

| Observation about real work | Product consequence |
| --- | --- |
| They already know the hostname; typing beats browsing | `Ctrl+K` fuzzy search opens a session in ~2 keystrokes; the tree is for discovery, not routine access |
| The same six commands get typed on every host | Snippets with variables, bound to hotkeys, insertable into the focused terminal |
| A dropped VPN should not lose an hour of work | Sessions are owned by the backend and survive browser reloads (§1.5) |
| "Is it just me or is that box down?" | Passive health state from real connection attempts, not an aggressive poller |
| Same fix on 12 hosts | Command Center with per-host results, not a broadcast into the void |
| Editing config over `cat`/`vi` in a 24×80 window is miserable | Monaco against SFTP, atomic save, optional pre-edit backup |
| Auth is repeated constantly | One SSH connection multiplexed into terminal, files, sysinfo, services |
| The dangerous command and the safe one look identical in a GUI | Explicit confirmation on destructive GUI actions, typed confirmation for multi-host |

## 1.3 Module map

Modules are packages with explicit interfaces. Nothing reaches across a module boundary
except through the interface, and the dependency graph is acyclic.

```
                        ┌───────────────────────────────────────┐
                        │              HTTP / WS API            │
                        └───────────────────────────────────────┘
                            │            │             │
       ┌────────────────────┴──┐  ┌──────┴───────┐  ┌──┴──────────────────┐
       │  Identity & Access    │  │  Inventory   │  │  Session Gateway    │
       │  ─────────────────    │  │  ──────────  │  │  ───────────────    │
       │  auth  rbac  tickets  │  │  hosts       │  │  registry           │
       │  sessions(browser)    │  │  folders     │  │  terminal bridge    │
       └───────────┬───────────┘  │  tags        │  │  rdp bridge         │
                   │              │  workspaces  │  │  ring buffer        │
                   │              └──────┬───────┘  └──┬──────────────────┘
                   │                     │             │
       ┌───────────┴───────────┐  ┌──────┴───────┐  ┌──┴──────────────────┐
       │  Credential Manager   │  │  Snippets    │  │  Protocol Engines   │
       │  envelope crypto      │  │  Sysinfo     │  │  ssh  sftp  guacd   │
       │  provider interface   │  │  Exec        │  │  tunnels            │
       └───────────┬───────────┘  └──────┬───────┘  └──┬──────────────────┘
                   │                     │             │
       ┌───────────┴─────────────────────┴─────────────┴──────────────────┐
       │   Store (SQLite today, Postgres-capable)   ·   Audit   ·  Events │
       └──────────────────────────────────────────────────────────────────┘
                   │
       ┌───────────┴──────────────────────────────────────────────────────┐
       │   Plugin host (Phase 4): host providers, resource providers,     │
       │   contextual actions, UI panels                                  │
       └──────────────────────────────────────────────────────────────────┘
```

| Module | Responsibility | Explicitly not its job |
| --- | --- | --- |
| `auth` | Password verification, browser sessions, CSRF, WS tickets, RBAC checks | Knowing what a host is |
| `credentials` | Encrypt, store, and hand out secrets to engines in-process | Deciding who may use a credential (that is `rbac`) |
| `inventory` | Hosts, folders, tags, search, health state | Connecting to anything |
| `ssh` | Dial (incl. jump chains), host-key verification, PTY sessions, exec, forwards | HTTP, WebSockets, persistence |
| `terminal` | Session registry, output ring buffer, WS attach/detach/replay | SSH specifics |
| `sftp` | Directory ops, streaming reads/writes, atomic writes, path safety | Queueing and retry |
| `transfer` | Durable queue, concurrency, progress, retry, history | Byte movement (delegates to `sftp`) |
| `rdp` | guacd handshake and instruction relay | Rendering (browser does that) |
| `tunnels` | Local/remote/SOCKS forward lifecycle | SSH transport details |
| `exec` | Multi-host command jobs: fan-out, timeouts, cancellation, aggregation | Interactive sessions |
| `sysinfo` | Best-effort facts and metrics over an existing SSH connection | Being a monitoring system |
| `audit` | Append-only structured event log with configurable verbosity | Deciding what is interesting (callers do) |
| `events` | Fan-out bus for progress/notifications to browser clients | Durability |
| `plugin` | Registering external providers and panels | Any specific integration |

## 1.4 Connection multiplexing

A host is not "a connection". A host has *one* SSH transport, and features are channels
on it.

```
  Browser tabs                        Backend                     Target host
  ┌──────────────┐
  │ Terminal     │──── WS ──┐
  ├──────────────┤          │      ┌───────────────────┐
  │ Files        │──── HTTP ─┼─────▶│  HostConnection   │──── one TCP/SSH ────▶ sshd
  ├──────────────┤          │      │  refcount, idle   │      · pty channel
  │ System       │──── HTTP ─┤      │  timer, keepalive │      · sftp subsystem
  ├──────────────┤          │      │                   │      · exec channels
  │ Services     │──── HTTP ─┘      └───────────────────┘      · direct-tcpip
  └──────────────┘
```

`HostConnection` is reference-counted. Opening the Files tab on a host with a live
terminal costs an SFTP subsystem channel, not a new authentication. When the last
consumer detaches, an idle timer (configurable, default 5 min) closes the transport.
Keepalives are sent at the SSH layer so NAT devices do not silently drop long sessions.

## 1.5 Session ownership — the backend owns the session

This is the most consequential design decision in the product, so it is stated plainly:

**A terminal session is a backend object. A browser WebSocket is a view of it.**

```
   t0  browser opens tab      ──▶ POST /sessions  ──▶ SSHSession created, PTY allocated
   t1  browser attaches WS    ──▶ stream stdout, forward stdin
   t2  laptop sleeps / VPN drops / user reloads
       └─ WS closes. SSHSession KEEPS RUNNING. Output accumulates in a ring buffer.
   t3  browser returns        ──▶ new ticket, re-attach same session id
       └─ replay ring buffer  ──▶ user sees the output produced while they were away
```

Consequences that fall out of this for free:

- Long `apt upgrade` runs survive a browser refresh.
- Reconnect is genuinely lossless up to the ring buffer size (default 256 KiB/session,
  configurable), not a fresh shell pretending to be the old one.
- Terminal geometry is server-side state, so a reattach restores the right `cols`/`rows`.
- Session recording is a tee on the same stream, not a browser-side hack.

And the safety rule that comes with it: **on reattach we replay output and never replay
input.** A pending keystroke that was in flight when the socket died is dropped, not
speculatively re-sent. Nothing is executed on the user's behalf after a reconnect.

## 1.6 State ownership summary

| State | Lives in | Why |
| --- | --- | --- |
| Hosts, folders, credentials, snippets | Database | Durable configuration |
| Live SSH/RDP sessions, PTY, ring buffers | Backend memory | Cannot be serialised; must outlive the tab |
| Transfer queue | Database + in-process workers | Must survive restart and report history |
| Tunnels | Backend memory + DB definition | Listener is a process resource |
| Tab layout, splits, focus, workspace | Browser (mirrored to DB per workspace) | Instant UI response; user-scoped |
| Theme, font, keybindings | Database (`user_settings`) | Follows the user across browsers |
| Secrets | Database, encrypted; plaintext only transiently in backend memory | §06 |
