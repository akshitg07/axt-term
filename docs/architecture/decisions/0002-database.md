# ADR 0002 — SQLite by default, with a Postgres-capable store layer

**Status:** Accepted · **Date:** 2026-08-19

## Context

The database holds configuration and history: hosts, folders, tags, encrypted credentials,
snippets, users, workspaces, transfer queue rows, audit events. It does **not** hold session
state — live PTYs and ring buffers are process memory by necessity. Target deployment is one
self-hosted instance on a LAN, administered by one person or a small team.

## Decision

SQLite via `modernc.org/sqlite` (pure Go, CGO-free) as the default and only Phase 1 backend,
behind store interfaces that keep a PostgreSQL implementation a contained addition.

Pragmas: `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`, `synchronous=NORMAL`.
One writer connection plus a read pool, which removes `SQLITE_BUSY` as a failure mode rather
than retrying around it.

## Reasoning

1. Realistic data volume is thousands of rows with a handful of writes per minute. Audit
   events are the only meaningful write stream and are far below SQLite's ceiling.
2. Zero operational burden: no container, no credentials, no tuning, no separate upgrade path.
   For self-hosted infrastructure software this is a feature, not a compromise.
3. Backup is `VACUUM INTO` against a running instance plus copying one file — a procedure an
   operator will actually follow.
4. In-process reads at microsecond latency keep host-list rendering instant.
5. It honours the explicit requirement to avoid infrastructure that is not genuinely needed.

## Consequences

- Single writer. Fine at this scale; the store layer serialises writes deliberately.
- No multi-replica backend. Already true for other reasons: live sessions pin a user to a
  process, so horizontal scaling requires session affinity regardless of the database.
- Portability discipline required: SQLite-specific SQL stays inside `internal/store/sqlite`,
  and migrations avoid dialect-only syntax.
- No down-migrations. Rollback is restore-from-backup, which for a single-file database is
  more trustworthy than rarely-tested reverse scripts. The upgrade guide makes taking a
  verified copy step one.

## When to revisit

Either of these makes Postgres the right answer, and it is scheduled as M35:

- More than one backend replica is required.
- Sustained audit write volume above a few hundred events per second.
