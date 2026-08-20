# AXT-Term Architecture

> Your remote infrastructure, one terminal away.

This directory is the design record for AXT-Term. It is written before the code and
updated with it — if an implementation diverges from these documents, the document is
wrong and must be fixed.

| Doc | Contents |
| --- | --- |
| [01-product-architecture.md](01-product-architecture.md) | What the product is, the module map, session lifecycle model |
| [02-technology-stack.md](02-technology-stack.md) | Stack comparison and the decisions, with reasoning |
| [03-system-architecture.md](03-system-architecture.md) | Runtime topology, process model, protocol engines |
| [04-data-model.md](04-data-model.md) | Database schema and relationships |
| [05-api.md](05-api.md) | REST + WebSocket contract |
| [06-security.md](06-security.md) | Threat model, credential handling, authn/authz, hardening |
| [07-ux-architecture.md](07-ux-architecture.md) | Workspace layout, navigation, keyboard model |
| [08-project-structure.md](08-project-structure.md) | Repository layout |
| [../roadmap.md](../roadmap.md) | Phased delivery plan and Phase 1 milestones |

## Decision log

Architecture Decision Records live in [decisions/](decisions/). Each records context,
options, the choice, and consequences. Superseded ADRs are kept, not deleted.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](decisions/0001-backend-language.md) | Go for the backend | Accepted |
| [0002](decisions/0002-database.md) | SQLite by default, Postgres-capable store layer | Accepted |
| [0003](decisions/0003-rdp-gateway.md) | guacd sidecar for RDP/VNC rather than a native client | Accepted |
| [0004](decisions/0004-session-ownership.md) | Sessions live in the backend, not in the browser tab | Accepted |
| [0005](decisions/0005-no-redis.md) | No Redis; in-process coordination + durable DB queues | Accepted |

## Non-negotiables

These constrain every decision that follows:

1. **The terminal is the product.** Every other panel is in service of it. If a feature
   makes the terminal slower or less reliable, it does not ship.
2. **Real protocols only.** Interactive SSH with a PTY, real SFTP, real RDP. No
   command-at-a-time shells pretending to be terminals.
3. **Credentials never reach the browser.** Not in a response body, not in localStorage,
   not in a WebSocket frame. The backend is the only holder of plaintext secrets.
4. **Works air-gapped.** No CDN, no telemetry, no cloud dependency, no outbound calls
   unless the operator configures an integration.
5. **Nothing fake.** An unimplemented feature is absent or explicitly labelled
   *Coming Soon*. A button that does nothing is a bug.
6. **Destructive actions are deliberate.** Confirmation for GUI-initiated destructive
   operations and for multi-host execution — but never censorship of what a user types
   into their own shell.
