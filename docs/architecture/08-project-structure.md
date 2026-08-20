# 8. Project Structure

A single repository with two build units — a Go backend that embeds a Vite-built SPA. Not a
JS monorepo (the frontend is one package; workspaces would add tooling for nothing), and not
split repositories (frontend and backend version together and the API contract is
generated across them).

```
axt-term/
├── README.md
├── LICENSE
├── CHANGELOG.md
├── Makefile                          # the only entrypoint a developer needs
├── docker-compose.yml                # production
├── docker-compose.dev.yml            # dev: live reload, test sshd, test Windows target
├── .env.example
├── .editorconfig
├── .golangci.yml
├── .github/workflows/ci.yml
│
├── docs/
│   ├── architecture/                 # this directory
│   │   ├── README.md  01-…  08-project-structure.md
│   │   └── decisions/                # ADRs
│   ├── installation.md
│   ├── configuration.md              # every AXT_* variable, generated from config struct tags
│   ├── deployment-docker.md
│   ├── development.md
│   ├── security.md                   # operator-facing hardening guide
│   ├── ssh.md   rdp.md   sftp.md
│   ├── backup-restore.md
│   ├── upgrade.md
│   ├── troubleshooting.md
│   └── plugin-development.md         # Phase 4
│
├── backend/
│   ├── go.mod  go.sum
│   ├── cmd/
│   │   ├── axt-term/main.go           # server: config → wiring → serve
│   │   └── axt-admin/                # user create/reset, key rotate, backup, audit prune,
│   │       └── main.go               # host import/export. Runs against the same DB.
│   ├── internal/
│   │   ├── config/                   # env parsing, validation, defaults, redacted dump
│   │   ├── logging/                  # slog setup, request-id, secret-scrubbing handler
│   │   ├── ids/                      # uuid + short-id helpers
│   │   ├── clock/                    # injectable time, for deterministic tests
│   │   ├── validate/                 # shared validators (hostname, port, mode, path, cidr)
│   │   ├── shellquote/               # POSIX quoting + fuzz corpus
│   │   │
│   │   ├── crypto/                   # envelope encryption, KEK loading, rotation
│   │   ├── store/
│   │   │   ├── store.go              # interfaces: UserStore, HostStore, CredentialStore, …
│   │   │   ├── models.go             # domain types shared by store + api
│   │   │   ├── sqlite/               # implementation, one file per aggregate
│   │   │   └── migrate/              # embedded migration runner
│   │   ├── migrations/*.sql          # embedded via //go:embed
│   │   │
│   │   ├── auth/                     # argon2 hashing, browser sessions, csrf, ws tickets
│   │   ├── rbac/                     # permission registry, route declarations, checks
│   │   ├── audit/                    # event recorder + query
│   │   ├── events/                   # in-process pub/sub → /ws/events
│   │   │
│   │   ├── inventory/                # hosts, folders, tags, search, health checker
│   │   ├── credentials/              # provider interface + local provider
│   │   │
│   │   ├── sshx/                     # SSH engine  (not "ssh": avoids stdlib-ish shadowing)
│   │   │   ├── dialer.go             # jump chains, timeouts, algorithm policy
│   │   │   ├── hostkey.go            # TOFU store-backed callback
│   │   │   ├── pool.go               # refcounted HostConnection pool
│   │   │   ├── session.go            # PTY session
│   │   │   ├── exec.go               # non-interactive exec with caps
│   │   │   └── forward.go            # local/remote/socks forwarding
│   │   ├── terminal/                 # session registry, ring buffer, recorder, ws bridge
│   │   ├── sftpx/                    # directory ops, streaming io, atomic write, path safety
│   │   ├── transfer/                 # durable queue + worker pool + progress
│   │   ├── rdp/                      # guacd client: handshake, instruction codec, relay
│   │   ├── tunnels/                  # tunnel lifecycle manager
│   │   ├── execjobs/                 # multi-host command jobs
│   │   ├── sysinfo/                  # facts, metrics, processes, services parsers
│   │   ├── snippets/                 # crud, variable rendering
│   │   ├── workspaces/
│   │   ├── discovery/                # Phase 3
│   │   ├── dockerx/                  # Phase 3
│   │   ├── kubex/                    # Phase 3
│   │   ├── plugin/                   # Phase 4
│   │   │
│   │   ├── httpx/
│   │   │   ├── server.go             # http.Server, timeouts, graceful shutdown
│   │   │   ├── router.go             # route table; startup fails on undeclared permission
│   │   │   ├── middleware/           # recover, reqid, log, ratelimit, authn, csrf, authz,
│   │   │   │                         # origin, securityheaders, confirm
│   │   │   ├── respond.go            # single JSON error/response shape
│   │   │   └── ws.go                 # upgrade + ticket validation helpers
│   │   ├── api/                      # handlers, one file per resource; thin, no business logic
│   │   └── web/                      # //go:embed of the built SPA + SPA fallback handler
│   │
│   ├── testdata/                     # fixtures: os-release samples, ps output, ssh keys
│   └── test/
│       ├── integration/              # real sshd container: ssh, sftp, tunnels, jump host
│       ├── authz_matrix_test.go      # every route × every role
│       └── testutil/                 # in-memory store, fake clock, test server harness
│
├── frontend/
│   ├── package.json  tsconfig.json  vite.config.ts  tailwind.config.ts
│   ├── index.html
│   ├── public/fonts/                 # Inter + JetBrains Mono, self-hosted
│   └── src/
│       ├── main.tsx  App.tsx
│       ├── app/
│       │   ├── shell/                # TopBar, Sidebar, TabStrip, SessionArea, Drawer, StatusBar
│       │   ├── providers/            # query client, theme, keybindings, toasts, ws
│       │   └── routes.tsx
│       ├── features/
│       │   ├── auth/                 # login, password change, session list
│       │   ├── hosts/                # tree, host form, quick connect, health
│       │   ├── credentials/
│       │   ├── terminal/             # xterm wrapper, addons, splits, recording, search
│       │   ├── files/                # single + dual pane, transfer queue UI
│       │   ├── editor/               # monaco wrapper, conflict dialog
│       │   ├── rdp/                  # guacamole client wrapper
│       │   ├── snippets/
│       │   ├── system/  processes/  services/  logs/
│       │   ├── command-center/
│       │   ├── tunnels/
│       │   ├── workspaces/
│       │   ├── audit/
│       │   └── settings/
│       ├── components/ui/            # Button, Input, Select, Dialog, Menu, Tree, Table,
│       │                             # VirtualList, Toast, Tooltip, Split, Confirm, Badge
│       ├── lib/
│       │   ├── api/                  # fetch client, CSRF, typed endpoints, error mapping
│       │   ├── ws/                   # reconnecting socket, framing codec, ticket flow
│       │   ├── store/                # zustand slices: tabs, panes, layout, palette, ui
│       │   ├── commands/             # command registry — palette + keybindings + menus
│       │   ├── keys/                 # binding resolution, scopes, conflict detection
│       │   ├── fuzzy.ts  format.ts  paths.ts
│       ├── styles/                   # tokens.css, themes.css, terminal-themes.ts
│       ├── types/api.gen.ts          # generated by tygo — do not edit
│       └── test/                     # setup, msw handlers, factories
│
├── deploy/
│   ├── Dockerfile                    # multi-stage: node build → go build → distroless
│   ├── caddy/Caddyfile
│   ├── guacd/README.md               # pinned image, why it exists, network isolation
│   └── systemd/axt-term.service      # non-Docker install path
│
├── scripts/
│   ├── dev.sh                        # backend + vite + test sshd, one command
│   ├── gen-types.sh                  # tygo; CI checks the result is committed
│   ├── test-sshd/                    # Dockerfile + fixtures for integration tests
│   └── backup.sh
│
└── tools/
    └── tygo.yaml
```

## Conventions

**`internal/` for everything.** Nothing in the backend is importable by another module until
there is a reason, which prevents accidental API surface.

**Handlers are thin.** `internal/api` decodes, calls a service, and encodes. Business logic
lives in the module packages, which take interfaces and are testable without HTTP.

**Store interfaces live with the consumer's needs, implementations in `sqlite/`.** Tests use
either the real SQLite store against a temp file (fast enough — it is in-process) or a fake,
chosen per test rather than dogmatically.

**One file per resource in `api/`, one per aggregate in `store/sqlite/`.** A file that
exceeds ~400 lines is a signal to split by aggregate, not to add a section comment.

**Frontend features are vertical slices.** A feature owns its components, hooks, and API
calls. Cross-feature sharing goes through `components/ui` or `lib/`, never by importing
another feature's internals — enforced by an ESLint boundary rule.

**No barrel `index.ts` re-export files.** They defeat tree-shaking and obscure the
dependency graph.

**Generated files are committed and CI-verified.** `types/api.gen.ts` carries a header
warning; `make types` regenerates; CI runs `git diff --exit-code`.
