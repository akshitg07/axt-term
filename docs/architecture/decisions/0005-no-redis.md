# ADR 0005 — No Redis or message broker

**Status:** Accepted · **Date:** 2026-08-19

## Context

The usual reflex for a session-holding, queue-running, event-publishing web application is
to add Redis. The requirement to avoid infrastructure that is not genuinely necessary means
this needs to be argued rather than assumed.

## Decision

No Redis, no message broker. Every coordination need is met in-process or in the database.

| Need | Solution |
| --- | --- |
| Browser session store | `auth_sessions` table plus a small in-memory cache. Sessions are already process-affine because live PTYs are (ADR 0004) |
| WebSocket ticket store | In-process map with a sweeper. Tickets have a 30-second TTL and are single-use, so durability is worthless |
| Transfer queue | `transfers` table plus an in-process worker pool. The queue *is* the history the UI shows, so persistence was required anyway |
| Progress and notification pub/sub | In-process `events` bus. Every WebSocket client is connected to this process |
| Rate limiting | In-process token buckets keyed by user and IP |
| Multi-host job state | `exec_jobs` / `exec_job_hosts` tables, because results must outlive the job for review and export |

## Reasoning

1. Redis would add a container, a failure mode, a version to upgrade, and a persistence
   decision — while adding no capability the application lacks.
2. Single-process deployment makes in-process pub/sub strictly better: no serialisation, no
   network hop, no delivery ambiguity.
3. Where durability genuinely matters (transfers, jobs), the database is the correct store
   because that data is also a product feature — history and export.
4. Redis-backed session sharing would not enable horizontal scaling anyway, because live
   sessions pin a user to a process. The hard problem there is session affinity, which Redis
   does not solve.

## Consequences

- Restarting the backend drops in-flight transfers to `interrupted` (retryable) and closes
  live sessions. Documented, with graceful shutdown notifying clients of the reason.
- Rate-limit counters reset on restart. Acceptable: lockout state that must survive restart
  lives in `users.locked_until` in the database.
- Multi-replica deployment in Phase 4 requires revisiting the events bus alongside the
  Postgres store and sticky routing — a single coordinated change, not five scattered ones.

## When to revisit

Together with ADR 0002's revisit triggers. If multi-replica arrives, the events bus needs a
cross-process transport; Postgres `LISTEN/NOTIFY` would then be evaluated first, since it
adds no new component.
