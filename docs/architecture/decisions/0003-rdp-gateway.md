# ADR 0003 — guacd sidecar for RDP rather than a native client

**Status:** Accepted · **Date:** 2026-08-19

## Context

Browsers cannot speak RDP, so something server-side must translate the RDP protocol into
something renderable in a canvas. RDP is a large protocol family: NLA/CredSSP
authentication, bitmap and RemoteFX codecs, clipboard, drive redirection, audio,
multi-monitor.

## Decision

Run `guacd` (the Apache Guacamole proxy daemon, Apache-2.0) as a sidecar container on an
internal Docker network. The AXT-Term Go backend acts as the Guacamole protocol *client*: it
opens the TCP connection, performs the handshake with server-side-decrypted credentials, and
relays the instruction stream to the browser over an authenticated WebSocket. The browser
renders with `guacamole-common-js`.

## Reasoning

1. guacd is a mature, widely deployed implementation of exactly this translation, including
   NLA, clipboard, drive redirection, and multi-monitor.
2. Its wire protocol is a simple length-prefixed `opcode,arg,arg;` instruction format that
   is straightforward to parse and relay from Go.
3. It also implements VNC, SSH, and Telnet, which makes two of the listed future protocols
   (VNC, Telnet) largely a configuration change rather than new engines.
4. Existing native Go RDP libraries are incomplete — partial NLA, no reliable
   RemoteFX/clipboard/audio — and completing one would be a multi-month project competing
   with a solved problem.

## Security properties this buys

The backend is the Guacamole client, so **connection parameters including credentials are
assembled server-side**. The browser receives only a single-use WebSocket ticket. This is
stronger than the common pattern where the client supplies connection parameters, and it is
the reason this architecture was chosen over embedding a Guacamole web client.

guacd's port is never published to the host, it runs as a non-root user, and instruction
relay enforces size and outstanding-stream limits so a hostile or malfunctioning daemon
cannot exhaust backend memory. Drive redirection and clipboard are per-host opt-in.

## Consequences

- One additional container in the deployment. Justified: it delivers a capability with no
  reasonable alternative, unlike a cache or broker which would add no capability.
- RDP is unavailable if guacd is not running. `/readyz` reports guacd reachability, and the
  RDP action is disabled with an explanatory message rather than failing at connect time.
- The Guacamole instruction codec must be implemented and tested in Go — a bounded,
  well-specified task.
- Version pinning matters; the guacd image tag is pinned and upgrades are documented.

## Alternatives rejected

- **Native Go RDP client** — libraries are incomplete; scope is disproportionate.
- **FreeRDP plus a custom WebSocket shim** — rebuilding guacd, worse.
- **VNC/xrdp installed on each target** — requires software on every Windows host.
- **Embedding the Java Guacamole web client** — a JVM plus servlet container, and it moves
  connection-parameter assembly toward the client.
