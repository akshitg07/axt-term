# AXT-Term

**Your remote infrastructure, one terminal away.**

A self-hosted, browser-based remote infrastructure workstation. Open one tab and
reach every machine you administer — Linux over SSH, Windows over RDP, files over
SFTP, containers, clusters — without switching between six applications.

> **Status: in development.** Phase 1 (MVP) is being built milestone by
> milestone; see [docs/roadmap.md](docs/roadmap.md) for exactly what works today
> and what is next. Features that are not implemented are absent or labelled
> *Coming Soon* — there are no buttons that do nothing.

---

## Why

Managing fifty Linux servers, ten Windows boxes, three Kubernetes clusters, and
the network gear between them currently means PuTTY, WinSCP, an RDP client,
FileZilla, several terminal windows, `docker`, `kubectl`, and a monitoring tab.
Each context switch costs a few seconds and a bit of attention, hundreds of times
a day.

AXT-Term collapses that into one workspace built around three ideas:

**The terminal is the product.** Real interactive SSH with a PTY over xterm.js —
not a form that runs one command at a time. Every other panel exists to serve the
terminal, and nothing navigates away from it.

**Sessions belong to the server, not the browser tab.** Reload the page, close
the laptop, lose the VPN — the PTY keeps running and its output is replayed when
you reattach. A long `apt upgrade` survives a network blip. Output is replayed;
input never is, so nothing runs on your behalf after a reconnect.

**Credentials never reach the browser.** Not in a response body, not in
`localStorage`, not in a WebSocket frame. SSH keys and RDP passwords are
encrypted at rest with a master key that is never stored in the database, and
they are decrypted only inside the backend at the moment of use.

## Architecture at a glance

```
Browser (xterm.js · Monaco · Guacamole client)
   │  HTTPS: session cookie + CSRF header
   │  WSS:   single-use ticket + origin validation
   ▼
Caddy — TLS, HSTS, security headers
   ▼
AXT-Term backend (single Go binary, embedded SPA)
   ├── session registry: live PTYs, output ring buffers
   ├── host connection pool: one SSH transport per host, many channels
   ├── protocol engines: ssh · sftp · guacd client · exec · sysinfo
   └── SQLite: inventory, encrypted credentials, audit
   │                                  │
   ▼ SSH / SFTP                       ▼ Guacamole protocol → guacd → RDP / VNC
Your infrastructure
```

**Stack:** Go 1.23 backend, React 19 + TypeScript + Vite + Tailwind frontend,
SQLite, guacd for RDP. No Redis, no message broker, no cloud dependency, no CDN —
everything works air-gapped on a private LAN.

The reasoning behind each of those choices, including the alternatives rejected
and why, is in [docs/architecture/](docs/architecture/).

## Documentation

| Document | Contents |
| --- | --- |
| [Architecture overview](docs/architecture/README.md) | Index and design non-negotiables |
| [Product architecture](docs/architecture/01-product-architecture.md) | Modules, connection multiplexing, session ownership |
| [Technology stack](docs/architecture/02-technology-stack.md) | Comparisons and decisions |
| [System architecture](docs/architecture/03-system-architecture.md) | Runtime topology, SSH/SFTP/RDP/WebSocket design |
| [Data model](docs/architecture/04-data-model.md) | Schema and relationships |
| [API](docs/architecture/05-api.md) | REST and WebSocket contract |
| [Security](docs/architecture/06-security.md) | Threat model, encryption, authn/authz, hardening |
| [UX architecture](docs/architecture/07-ux-architecture.md) | Workspace, navigation, keyboard model |
| [Project structure](docs/architecture/08-project-structure.md) | Repository layout |
| [Decision records](docs/architecture/decisions/) | ADRs with context and consequences |
| [Roadmap](docs/roadmap.md) | Phased plan and milestone acceptance criteria |
| [Configuration reference](docs/configuration.md) | Every environment variable, generated from code |

## Development

Requires Go 1.23+ and (from M7) Node 22+.

```bash
git clone <repository-url> axt-term
cd axt-term
make help          # every available target

make test          # backend unit tests
make test-race     # with the race detector
make run           # server on :8080 with development defaults, data in ./data
make lint          # golangci-lint
make ci            # everything CI runs
```

`make run` writes to `./data` and uses `AXT_ENV=development`, which relaxes the
TLS expectations that production enforces. Configuration is validated at startup
and the process refuses to run on an invalid value, reporting every problem at
once rather than one restart at a time.

## Security

Security decisions are documented rather than assumed. The short version:

- **Credentials** — AES-256-GCM envelope encryption; per-credential data keys
  wrapped by a master key held outside the database; associated data binds every
  ciphertext to its own record and field, so relocating a blob fails
  authentication instead of decrypting.
- **Sessions** — Argon2id passwords, `HttpOnly` `Secure` `SameSite` cookies
  stored only as hashes, CSRF double-submit, strict origin validation. Nothing in
  `localStorage`.
- **WebSockets** — single-use 30-second tickets bound to user, session, and
  client address, because cookie-only WebSocket authentication is the standard
  weak point.
- **SSH** — mandatory host-key verification; trust-on-first-use with an explicit
  fingerprint prompt, and a key that changes after being trusted is a hard
  failure with no in-flow override.
- **Destructive actions** — GUI-initiated deletions, multi-host execution, and
  service stops require explicit confirmation bound to the exact request. What
  you type into your own interactive shell is never inspected or blocked.

Full detail, including what AXT-Term explicitly does *not* protect against, is in
[docs/architecture/06-security.md](docs/architecture/06-security.md).

To report a vulnerability, please open a private security advisory rather than a
public issue.

## Licence

See [LICENSE](LICENSE).

AXT-Term takes workflow inspiration from tools that got things right — orthodox
file managers, terminal multiplexers, modern editors, and the Apache Guacamole
protocol — and uses guacd under the Apache 2.0 licence for RDP and VNC
translation. It contains no code, branding, or assets from any commercial product
it is compared to.
