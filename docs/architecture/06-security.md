# 6. Security Architecture

AXT-Term holds the keys to an entire estate. Compromising it is worse than compromising any
single host it manages, so the security posture is treated as a feature of the product, not
a checklist appended to it.

## 6.1 Threat model

| Adversary | Capability assumed | Primary mitigations |
| --- | --- | --- |
| Network attacker on the LAN | Passive sniffing, ARP spoofing | TLS 1.3 required for `Secure` cookies; SSH host-key pinning defeats MITM on the target hop |
| Malicious/compromised browser origin | Can make cross-origin requests, run JS on another site | SameSite cookies, CSRF double-submit, `Origin`/`Sec-Fetch-Site` validation on HTTP *and* WS |
| Authenticated low-privilege user | Valid session, wants privilege escalation | RBAC enforced server-side on every route; `credential.use` ≠ `credential.read`; audit trail |
| Attacker with a copy of the database file | Stolen backup, snapshot, or volume | Envelope encryption with a KEK that is never in the database; stealing the DB alone yields no secrets |
| Attacker with filesystem read on the host | Can read DB *and* environment | Correctly game over for secrets-at-rest. Documented honestly; mitigated by external secret providers (Vault) in Phase 4 |
| Malicious target host | Controls what it sends back over SSH/RDP | Output is data, never evaluated; terminal escape handling is xterm.js's; guacd instruction size caps |
| Curious/hostile operator of a shared instance | Legitimate admin access | Append-only audit log with no UI delete path; configurable command logging |

**Out of scope, stated plainly:** AXT-Term does not defend against a root-level compromise
of the machine it runs on, and it cannot protect against a user who has legitimate shell
access to a target choosing to do damage there.

## 6.2 Credential encryption

Envelope encryption. Two levels so that rotating the master key does not require touching
every secret's ciphertext, and so each secret has its own key.

```
                 AXT_MASTER_KEY (32 bytes, base64)        ┐
                   or AXT_MASTER_KEY_FILE                 │ never in the database
                   or Argon2id(AXT_MASTER_PASSPHRASE,     │
                              salt from crypto_keys)      ┘
                              │
                              ▼
                     KEK  (AES-256-GCM)
                              │
                   wraps ─────┴──────────────────────┐
                              ▼                      ▼
              credentials.dek_wrapped         (per credential)
                              │
                              ▼
                     DEK  (AES-256-GCM)
                              │
                   encrypts ──┴───────────────────────┐
                              ▼                       ▼
                   password ciphertext      private_key ciphertext
```

**Associated data binds ciphertext to its location**, so a row cannot be copied to a
different credential or field and still decrypt:

```
DEK wrap AAD    = "axt:dek:v1|"    ‖ credential_id ‖ "|" ‖ key_version
secret AAD      = "axt:secret:v1|" ‖ credential_id ‖ "|" ‖ field
```

Blob format: `version(1) ‖ nonce(12) ‖ ciphertext ‖ tag(16)`. Nonces come from
`crypto/rand` per encryption; a 96-bit random nonce per new DEK has negligible collision
risk, and DEKs are single-credential.

**Startup validation.** The backend refuses to start if the master key is missing,
shorter than 32 bytes, or fails a decrypt-canary check against a known ciphertext in
`settings`. A silent start with the wrong key would present an empty-looking credential
store and invite a user to overwrite real data.

**Rotation.** `axt-admin key rotate --new-key-file …` inserts a new `crypto_keys` row,
rewraps every DEK, and retires the old version in one transaction. Secret ciphertext is
untouched, so rotation is fast and low-risk. The command is audited.

**In-memory handling.** Plaintext secrets are decrypted at the moment of use, passed to the
SSH/guacd layer, and the backing slices are zeroed. Go's GC means this is best-effort, not
a guarantee — stated here rather than implied. Secrets are never placed in strings where
avoidable (strings are immutable and un-zeroable), never in log fields, never in error
messages, and never in a struct that has a JSON tag.

**Log safety is enforced by tests**, not discipline alone: a test feeds known secret values
through credential creation, connection, and failure paths, and asserts none appear in
captured log output.

## 6.3 Authentication

**Passwords:** Argon2id, `m=64 MiB, t=3, p=4`, 16-byte salt, 32-byte output, stored in the
standard encoded form so parameters can be upgraded and old hashes rehashed on next login.
Failed logins increment a counter; 10 failures locks the account for 15 minutes. The
password comparison path takes similar time on unknown users (a dummy hash is verified) so
timing does not enumerate accounts.

**Browser sessions:** 256-bit random token, delivered as a cookie, stored only as a
SHA-256 hash. Sliding expiry (`AXT_SESSION_IDLE_TIMEOUT`, default 8 h) with an absolute cap
(`AXT_SESSION_MAX_LIFETIME`, default 7 d). Rotated on login and on password change.

```
Set-Cookie: __Host-axt_session=<token>; Path=/; HttpOnly; Secure; SameSite=Lax
Set-Cookie: __Host-axt_csrf=<token>;    Path=/;            Secure; SameSite=Lax
```

`HttpOnly` on the session cookie means XSS cannot exfiltrate it. The CSRF cookie is
deliberately JS-readable — that is the mechanism — and is useless without the session
cookie. The `__Host-` prefix pins cookies to the exact origin with no subdomain scope;
it requires `Secure`, so plain-HTTP deployments fall back to unprefixed names and the
startup log warns about it.

**No tokens in `localStorage`.** Ever. A `localStorage` token is readable by any injected
script and survives beyond the session; the requirement in §57 is architectural here, not
a convention.

## 6.4 CSRF and origin validation

Layered, because each layer fails differently:

1. `SameSite=Lax` blocks the common cross-site form/subresource cases.
2. Double-submit: every non-`GET`/`HEAD` request must send `X-AXT-CSRF` matching the
   `axt_csrf` cookie, compared with `crypto/subtle.ConstantTimeCompare`, and additionally
   matched against `auth_sessions.csrf_hash` so a stale token from a revoked session fails.
3. `Origin` (or `Referer` fallback) must match a configured allow-list
   (`AXT_ALLOWED_ORIGINS`, defaulting to `AXT_PUBLIC_URL`). `Sec-Fetch-Site: cross-site` is
   rejected outright.
4. No CORS. `Access-Control-Allow-Origin` is never emitted; the SPA is same-origin because
   the backend serves it.

## 6.5 WebSocket authentication

Browsers cannot set headers on a WebSocket handshake, which is why cookie-only WS auth is
the standard weak point (cross-site WebSocket hijacking: cookies are sent on cross-origin
WS upgrades, and no preflight applies).

AXT-Term uses **single-use tickets**:

```
POST /api/v1/sessions/{id}/ticket     ← authenticated, CSRF-checked, origin-checked
  → { ticket: <32 random bytes, base64url>, expires_in: 30 }

WS /ws/terminal?ticket=…
  server: consume ticket atomically (compare-and-delete) and verify
          · not expired (30 s)
          · not previously used
          · bound to this user, this session id, and this client IP
          · Origin header in the allow-list
          · session exists and belongs to this user
```

A leaked URL is worthless 30 seconds later, and worthless immediately if already used.
Tickets live in a small in-process map with a sweeper — they are single-process by nature,
like the sessions they authorise.

Origin is still validated on the upgrade as defence in depth, and the ticket is never
logged (query strings are redacted in the access log).

## 6.6 SSH security

| Control | Implementation |
| --- | --- |
| Host key verification | Mandatory. TOFU with an explicit UI prompt, or `strict` mode. Mismatch is a hard failure with no in-flow override (§3.3) |
| Algorithm policy | Go's `x/crypto/ssh` defaults, with SHA-1 signatures and CBC ciphers excluded. Legacy network gear can be opted in per host via `AXT_SSH_LEGACY_ALGOS` and the host page shows a warning badge |
| No `ssh` binary | All SSH is in-process via the library. Nothing is passed to a shell, so there is no argument-injection surface |
| Jump chains | Depth-limited to 5, cycle-detected, each hop independently authenticated and verified |
| Agent forwarding | Off by default; per-host opt-in, because a forwarded agent lets a compromised host authenticate as the user elsewhere |
| Connection limits | Per-user session cap and per-host connection cap; prevents one user exhausting file descriptors |
| Idle timeout | Configurable; default closes an unattached session after 30 min and audits the reason |

**Command injection surface: none by construction.** Commands the backend runs for
`sysinfo`, processes, and services are fixed strings with parameters passed through a
shell-quoting helper (`'` wrapping with `'\''` escaping), and the helper is fuzz-tested.
Service unit names and PIDs are validated against strict patterns
(`^[A-Za-z0-9@:._\\-]+\.(service|socket|timer|target)$`, `^[0-9]{1,7}$`) *before* they reach
a command line. Nothing user-supplied is concatenated into a command without both.

## 6.7 RDP security

- Credentials are decrypted server-side and written only into the guacd handshake, on the
  internal Docker network. The browser holds a ticket, never a password. Grep the frontend
  bundle for a domain/username/password field and there is nothing to find.
- guacd's port is not published to the host; only the backend container can reach it.
- `guacd` runs as a non-root user in its container.
- Drive redirection and clipboard are per-host opt-in, off by default: file redirection is
  a bidirectional data path into a Windows host and should be a decision, not a default.
- Instruction relay enforces a maximum instruction size and a maximum outstanding stream
  count, so a hostile or malfunctioning guacd cannot exhaust backend memory.

## 6.8 File operation safety

Path handling for every SFTP operation, in order:

1. Reject empty paths, paths containing a NUL byte, and non-absolute paths.
2. `path.Clean` the value (POSIX semantics — the remote is not the backend's filesystem).
3. Reject any result still containing `..` after cleaning.
4. If `AXT_SFTP_ROOT` is configured for the host, require the cleaned path to be within it
   using a prefix check on path *segments*, not a string prefix (so `/opt/app-evil` does not
   pass a `/opt/app` root).
5. Do not resolve symlinks to escape the root: the remote server enforces its own
   permissions, and the session user's rights are the real boundary. This is documented so
   nobody mistakes `AXT_SFTP_ROOT` for a security sandbox — it is a guardrail against
   accidents, and the SSH user's permissions are the actual control.

Additional protections:

- **Download**: streamed, never staged in a temp file on the backend, so a large download
  cannot fill the server's disk.
- **Upload**: streamed, with a configurable maximum request size, and a check that the
  target directory exists before consuming the body.
- **Editor write**: atomic temp-write + `fsync` + `chmod` to preserve the original mode +
  `rename` (§3.4). `expected_mtime` guards against clobbering concurrent edits.
- **Filename handling**: names from the remote are treated as opaque bytes; the UI renders
  them with control characters and bidirectional-override characters escaped, so a file
  named with an embedded ANSI sequence or RTL override cannot spoof the UI.
- **Archive extraction** is not implemented in Phase 1 — Zip-Slip is a class of bug worth
  not having yet.

## 6.9 Transport and HTTP hardening

Response headers on every response:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains     (when TLS)
Content-Security-Policy: default-src 'self';
                         script-src 'self' 'wasm-unsafe-eval';
                         style-src 'self' 'unsafe-inline';
                         img-src 'self' data: blob:;
                         font-src 'self';
                         connect-src 'self' ws: wss:;
                         frame-ancestors 'none';
                         base-uri 'none';
                         object-src 'none';
                         form-action 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), camera=(), microphone=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store          (on all /api/ responses)
```

`style-src 'unsafe-inline'` is required by Monaco's dynamic styling; it is a real
concession and is recorded here rather than hidden. `script-src` has no `unsafe-inline` and
no `unsafe-eval` — `wasm-unsafe-eval` covers xterm.js's WebGL/WASM paths without opening
JS eval. There is no CDN entry anywhere in the policy, which is both a security property
and what makes air-gapped operation work.

TLS: Caddy terminates with TLS 1.2 minimum (1.3 preferred), modern cipher suites, and
either an operator-provided certificate or a local CA for LAN use. HTTP redirects to HTTPS.

## 6.10 Authorization

Every route declares its required permission at registration time, and the router refuses
to start if a route has no declaration — an unprotected endpoint becomes a startup failure
instead of a vulnerability discovered later.

```go
r.Post("/api/v1/hosts", perm("host.write"), h.CreateHost)
r.Get("/api/v1/audit",  perm("admin.audit"), h.ListAudit)
```

Object-level checks sit alongside permission checks: a `viewer` cannot read another user's
transfers or session records, and non-admins see only their own audit entries. Resource
ownership is verified in the query (`WHERE user_id = ?`), not by filtering after loading —
so a mistake yields "not found" rather than a leak.

## 6.11 Audit logging

Recorded for authentication, authorization denials, host and credential mutations, session
open/close, file writes and deletes, permission changes, service and process actions,
multi-host execution, tunnel lifecycle, host-key trust decisions and mismatches, and
administrative settings changes.

Command logging is configurable at three levels because terminal content routinely contains
secrets that must not be duplicated into a second store:

| Mode | Recorded |
| --- | --- |
| `off` | Session open/close only |
| `commands` (default) | Command lines submitted through the UI — snippets, Command Center, service actions. **Not** raw interactive keystrokes |
| `full` | Full session recording to disk (asciicast v2), opt-in per host, with a visible indicator in the terminal toolbar while active |

`full` mode passes output through a redaction filter for high-confidence patterns
(`password:` prompts, `PRIVATE KEY` blocks, `AWS_SECRET`-style assignments) and the docs
state plainly that redaction is best-effort — a recording is sensitive material and should
be treated as such.

Recordings are written under a dedicated directory with `0600` permissions, are never
world-readable in the container, and are excluded from the metrics endpoint and from any
list a non-owner can reach.

## 6.12 Input validation

Every request body is decoded into a typed struct with `DisallowUnknownFields`, then
validated — never `map[string]any` inspected ad hoc. Validation is centralised per type so
the same rules apply to create and update paths. Specific rules worth naming: hostnames
match a DNS/IP pattern; ports are range-checked; file modes match `^0?[0-7]{3,4}$`; CIDRs
for discovery are parsed and restricted to private ranges by default with a maximum of
`/16`; snippet variable names match `^[a-z_][a-z0-9_]*$`; and UUID path parameters are
parsed before any query runs.

## 6.13 Security testing

Part of the test suite, not a separate exercise:

- Path traversal: a table of adversarial paths (`../`, encoded variants, absolute escapes,
  NUL bytes, unicode look-alikes, symlink games) asserted rejected on every FS endpoint.
- Command injection: shell-quoting fuzzed; unit names and PIDs asserted rejected.
- Credential encryption: round-trip, AAD mismatch rejection, tamper detection, wrong-key
  rejection, rotation correctness.
- Secret leakage: known values asserted absent from logs, API responses, and error strings.
- CSRF: every mutating route asserted to reject a missing/mismatched token.
- WS auth: missing, expired, reused, wrong-user, wrong-session, and wrong-origin tickets
  all asserted rejected.
- Authorization: a matrix test walks every route × every role and asserts the expected
  allow/deny — so adding a route without a permission fails a test as well as startup.
- Rate limiting: lockout and throttle behaviour.
- Host keys: TOFU accept, match, and mismatch-hard-fail paths.
