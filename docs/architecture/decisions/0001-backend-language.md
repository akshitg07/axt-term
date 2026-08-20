# ADR 0001 — Go for the backend

**Status:** Accepted · **Date:** 2026-08-19

## Context

The backend multiplexes hundreds of long-lived byte streams (SSH PTYs, SFTP transfers, RDP
instruction relays, tunnels) with a latency requirement on keystroke echo, and it must ship
as a small self-hosted artifact. The realistic candidates were Go and Node.js/TypeScript.

## Decision

Go 1.23+.

## Reasoning

1. `golang.org/x/crypto/ssh` is maintained by the Go team and exposes the transport
   primitives this product needs directly: per-client `Dial` composes jump chains,
   `Client.Listen` implements remote forwards, `RequestSubsystem` gives SFTP. Node's `ssh2`
   is capable but abstracts these away and is effectively single-maintainer.
2. `pkg/sftp` pipelines requests and has `ReaderFrom`/`WriterTo` fast paths; it saturates a
   gigabit link. Node SFTP throughput is bound by buffer copies and event-loop scheduling.
3. Goroutine-per-stream matches the problem exactly. 500 live PTYs cost tens of MB with no
   scheduling cliff, and backpressure is `io.Copy` rather than hand-plumbed
   `pause()`/`resume()` across every hop.
4. A single static binary in a distroless image (~25 MB) is a materially better
   self-hosting story than a Node runtime plus `node_modules`.
5. Official `client-go` and `docker/docker` clients for Phase 3.

## Consequences

- **Cost:** no native type sharing with the TypeScript frontend. Mitigated by `tygo`
  generating `frontend/src/types/api.gen.ts` from Go structs, with the generated file
  committed and CI failing when stale.
- **Cost:** two languages in the repository, so two toolchains in CI and in the dev setup.
  Accepted; the boundary is clean and the `Makefile` hides it.
- Contributors need Go familiarity, which is a smaller pool than TypeScript.

## Alternatives rejected

- **Node/TypeScript** — the type-sharing advantage is recoverable with codegen; Go's
  streaming and library advantages are not recoverable in Node.
- **Rust** — strong technically, but a thinner SSH/SFTP ecosystem and a real velocity cost
  with no requirement here that demands it.
- **Python** — `paramiko` is mature but slow, and hundreds of concurrent streams fit the
  runtime poorly.
- **Java** — the reference Guacamole client is excellent, but a JVM per deployment
  contradicts the small-appliance goal. We use guacd (C) directly instead; see ADR 0003.
