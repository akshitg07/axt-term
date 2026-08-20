# 5. API Architecture

Base path `/api/v1`. JSON in, JSON out, `snake_case` fields. Every mutating request
carries the CSRF header. Every response carries `X-Request-Id`.

## 5.1 Conventions

**Errors** use one shape, always, so the frontend has exactly one error renderer:

```json
{
  "error": {
    "code": "host_unreachable",
    "message": "dial tcp 10.0.4.12:22: connect: connection refused",
    "details": { "host_id": "…", "hop": "bastion-1" },
    "request_id": "01J8…"
  }
}
```

`code` is a stable machine-readable identifier; `message` is for humans and is safe to
display. Validation failures return `422` with `details.fields`.

| Status | Meaning here |
| --- | --- |
| 400 / 422 | Malformed request / validation failure |
| 401 | No or expired session |
| 403 | Authenticated but lacking the permission, or CSRF/Origin rejection |
| 404 | Not found, or not visible to this user |
| 409 | Conflict (duplicate name, host-key mismatch requiring resolution) |
| 412 | Confirmation required — see §5.9 |
| 423 | Account locked |
| 429 | Rate limited, with `Retry-After` |
| 502 | Upstream target failure (SSH dial, guacd) |
| 504 | Target timed out |

**Pagination** is cursor-based on list endpoints that can grow without bound (audit,
transfers, session history): `?limit=100&cursor=…` → `{"items":[…],"next_cursor":"…"}`.
Inventory endpoints return complete sets — a few thousand hosts is one small response and
client-side filtering is instant, which matters more than protocol purity here.

**Timestamps** are RFC 3339 UTC strings everywhere.

## 5.2 Authentication

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/auth/login` | `{username, password, totp?}` → sets `axt_session` + `axt_csrf` cookies, returns user and permissions. Rate limited per IP and per username. Constant-time-ish failure path. |
| `POST` | `/auth/logout` | Revokes the current session |
| `GET` | `/auth/me` | `{user, permissions[], must_change_password}` |
| `POST` | `/auth/password` | `{current_password, new_password}`; revokes all other sessions |
| `GET` | `/auth/sessions` | This user's active browser sessions |
| `DELETE` | `/auth/sessions/{id}` | Revoke one |
| `POST` | `/auth/totp/enroll` · `/auth/totp/confirm` · `/auth/totp/disable` | Phase 2 |

Login responses never distinguish "no such user" from "wrong password".

## 5.3 Inventory

```
GET    /folders                        tree, nested
POST   /folders                        {name, parent_id?, icon?, color?}
PATCH  /folders/{id}
DELETE /folders/{id}?strategy=orphan|cascade
POST   /folders/{id}/move              {parent_id, sort_order}

GET    /hosts?q=&folder_id=&tag=&protocol=&os_family=&favorite=&sort=
POST   /hosts
GET    /hosts/{id}
PATCH  /hosts/{id}
DELETE /hosts/{id}
POST   /hosts/{id}/duplicate
POST   /hosts/{id}/favorite            {is_favorite}
POST   /hosts/{id}/test                probe: TCP reach, SSH banner, auth check; no shell
GET    /hosts/{id}/health
POST   /hosts/import                   {format: 'ssh_config'|'axt_json'|'csv', content}
GET    /hosts/export?format=axt_json   never includes secrets
GET    /hosts/{id}/actions             contextual action set for this host's protocol/OS

GET    /tags
POST   /tags
DELETE /tags/{id}

GET    /host-keys?hostname=&port=
DELETE /host-keys/{id}                 revoke trust; admin only, audited
POST   /host-keys/{id}/trust           resolve a pending TOFU decision
```

`GET /hosts/{id}/actions` is what keeps §42 honest. The server decides which actions apply
to a Linux SSH host versus a Windows RDP host versus a switch, so the frontend renders a
list rather than hard-coding capability guesses — and a plugin can extend that list in
Phase 4 without a frontend change.

`POST /hosts/{id}/test` deliberately stops at authentication. It answers "will connecting
work" without opening a shell or leaving a session record.

## 5.4 Credentials

```
GET    /credentials                    metadata only: kind, username, key_fingerprint,
                                       key_type, provider, last_used_at, in_use_by_count
POST   /credentials                    secrets accepted here, write-only
GET    /credentials/{id}               metadata only — no secret field exists in the response type
PATCH  /credentials/{id}               omitted secret fields are left unchanged
DELETE /credentials/{id}               409 if referenced, unless ?force=true
POST   /credentials/{id}/verify        {host_id} → attempts auth, returns ok/failure reason
GET    /credentials/{id}/usage         hosts referencing it
```

There is no endpoint that returns a secret. Not for admins, not for export. The Go response
struct has no field for it, so it cannot regress by accident — and a test asserts that
serialising a credential never emits any known secret value.

## 5.5 Sessions and WebSockets

```
POST   /sessions                       {host_id, protocol, cols, rows, purpose?}
                                       → {session_id, state, host, pending_hostkey?}
GET    /sessions                       live sessions for this user
GET    /sessions/{id}
DELETE /sessions/{id}                  close
POST   /sessions/{id}/ticket           → {ticket, expires_in: 30}   single-use
POST   /sessions/{id}/resize           {cols, rows}   (also available as a WS control frame)
POST   /sessions/{id}/recording        {enabled: bool}
GET    /sessions/{id}/recording        download asciicast v2
GET    /sessions/recent?limit=20       history for the Recent panel

WS     /ws/terminal?ticket=…           binary I/O + JSON control (§3.5)
WS     /ws/rdp?ticket=…                Guacamole instruction stream
WS     /ws/events                      per-user event stream
```

If `POST /sessions` encounters an untrusted host key, it returns `200` with
`state: "pending_hostkey"` and the fingerprint. The client shows the trust prompt and calls
`POST /host-keys/{id}/trust`; the dial then continues. The connection is held open awaiting
the decision, with a timeout — no silent trust, no lost connection attempt.

### `/ws/events` payloads

```json
{"t":"transfer.progress","id":"…","transferred_bytes":125829120,"speed_bps":11534336,"eta_s":8}
{"t":"transfer.done","id":"…","status":"completed"}
{"t":"host.health","host_id":"…","status":"offline","latency_ms":null}
{"t":"session.state","session_id":"…","state":"disconnected","reason":"remote closed"}
{"t":"exec.progress","job_id":"…","host_id":"…","status":"completed","exit_code":0}
{"t":"notification","level":"error","title":"Transfer failed","message":"…"}
```

One socket per browser tab-group for all of this — not one per feature. Terminal I/O stays
on its own socket so a burst of events cannot delay keystroke echo.

## 5.6 Files (SFTP)

```
GET    /hosts/{id}/fs/list?path=/etc&show_hidden=true
GET    /hosts/{id}/fs/stat?path=
POST   /hosts/{id}/fs/mkdir            {path}
POST   /hosts/{id}/fs/touch            {path}
POST   /hosts/{id}/fs/rename           {from, to}
POST   /hosts/{id}/fs/remove           {paths[], recursive}         confirmation required
POST   /hosts/{id}/fs/chmod            {path, mode: "0644", recursive}
POST   /hosts/{id}/fs/chown            {path, uid, gid, recursive}  confirmation required
POST   /hosts/{id}/fs/symlink          {target, link}
GET    /hosts/{id}/fs/download?path=   streamed; supports Range
POST   /hosts/{id}/fs/upload?path=     streamed body; Content-Length drives progress
GET    /hosts/{id}/fs/read?path=       editor load: {content, encoding, mode, size, truncated}
PUT    /hosts/{id}/fs/write            {path, content, expected_mtime?, backup?}
GET    /hosts/{id}/fs/search?path=&pattern=&max_depth=&max_results=
GET    /hosts/{id}/fs/disk-usage?path=
```

`PUT /fs/write` takes `expected_mtime` and returns `409` if the file changed since it was
read — losing someone else's edit to `nginx.conf` because two people had it open is a real
outage, and optimistic concurrency costs one column.

`list` returns for each entry: name, type, size, mode (octal and `rwxr-xr-x` rendering),
uid/gid with resolved names when cheaply available, mtime, symlink target, and whether it
is readable/writable by the session user.

## 5.7 Transfers

```
GET    /transfers?status=&limit=&cursor=
POST   /transfers/{id}/cancel
POST   /transfers/{id}/retry
DELETE /transfers/{id}                 remove from history
POST   /transfers/clear-completed
```

Uploads and downloads initiated from the UI create `transfers` rows and report progress
over `/ws/events`, so the queue is a real record rather than a per-tab illusion.

## 5.8 Operations panels

```
GET    /hosts/{id}/system                          facts + current CPU/RAM/disk sample
GET    /hosts/{id}/processes?sort=cpu&limit=200
POST   /hosts/{id}/processes/{pid}/signal          {signal: "TERM"|"KILL"|"HUP"}  confirmation
GET    /hosts/{id}/services?state=
POST   /hosts/{id}/services/{unit}/{action}        start|stop|restart|reload|enable|disable
GET    /hosts/{id}/services/{unit}/logs?lines=200&follow=false
GET    /hosts/{id}/logs/tail?path=&lines=200       WS upgrade when follow=true
GET    /hosts/{id}/network                         interfaces, listening sockets, routes
```

Phase 2 for processes and services; Phase 3 for Docker and Kubernetes:

```
GET    /hosts/{id}/docker/containers|images|volumes|networks
POST   /hosts/{id}/docker/containers/{cid}/{action}
GET    /hosts/{id}/docker/containers/{cid}/logs
POST   /hosts/{id}/docker/containers/{cid}/exec    → {session_id} → terminal WS

GET    /clusters
GET    /clusters/{id}/{resource}?namespace=
GET    /clusters/{id}/pods/{ns}/{name}/logs
POST   /clusters/{id}/pods/{ns}/{name}/exec        → {session_id} → terminal WS
POST   /clusters/{id}/port-forward
```

Docker "exec" and Kubernetes "exec" return a `session_id` and reuse the *same* terminal
WebSocket path as SSH. One terminal implementation, three sources.

## 5.9 Confirmation gate for destructive operations

Rather than scattering confirmation logic across handlers, one middleware handles it.
Destructive endpoints and flagged commands require `X-AXT-Confirm`:

```
POST /hosts/{id}/fs/remove   {paths:["/var/log/app"],"recursive":true}
   → 412 {"error":{"code":"confirmation_required",
           "details":{"confirm_token":"…","summary":"Recursively delete /var/log/app on prod-web01",
                      "severity":"high","typed_confirmation":"prod-web01"}}}

POST /hosts/{id}/fs/remove   X-AXT-Confirm: <confirm_token>
   → 200
```

The token is bound to the exact request body hash, the user, and a 60-second TTL, so a
confirmation cannot be replayed against a different target. `typed_confirmation` tells the
UI to require the user to type the host name — reserved for high-severity actions
(recursive delete, multi-host destructive execution, service stop on many hosts).

Command Center classifies commands against a pattern set (`rm -rf`, `mkfs`, `dd of=`,
`shutdown`, `reboot`, `kill -9 1`, `systemctl stop`, `docker rm`, `kubectl delete`,
`>` onto a device, and similar) and escalates the confirmation for those. Two rules from
§60 hold firmly: this classifier gates **GUI-initiated and multi-host** operations only,
and it never blocks or rewrites what a user types into their own interactive terminal.
Intent cannot be inferred reliably, so the interactive shell stays uncensored.

## 5.10 Command Center, snippets, tunnels, audit, settings

```
POST   /exec/batch                     {host_ids[], command, mode, concurrency,
                                        timeout_s, stop_on_error}
GET    /exec/jobs?limit=&cursor=
GET    /exec/jobs/{id}                 aggregated results
POST   /exec/jobs/{id}/cancel
POST   /exec/jobs/{id}/retry-failed
GET    /exec/jobs/{id}/export?format=json|csv|txt

GET    /snippets?q=&folder_id=&os_family=
POST   /snippets      PATCH /snippets/{id}      DELETE /snippets/{id}
POST   /snippets/{id}/render           {host_id, vars} → resolved text, never executed here
POST   /snippets/import   GET /snippets/export
GET    /snippet-folders   POST /snippet-folders

GET    /tunnels    POST /tunnels    PATCH /tunnels/{id}    DELETE /tunnels/{id}
POST   /tunnels/{id}/start|stop      GET /tunnels/{id}/logs

GET    /audit?from=&to=&user_id=&host_id=&action=&result=&q=&limit=&cursor=
GET    /audit/export?format=csv|jsonl
GET    /audit/actions                  distinct action keys, for filter UI

GET    /settings     PUT /settings     (admin)
GET    /me/settings  PUT /me/settings  (theme, terminal font/size/theme, keybindings)
GET    /search?q=                      unified: hosts, folders, tags, snippets, workspaces, recent

GET    /healthz      liveness, no auth
GET    /readyz       DB + migrations + guacd reachability
GET    /metrics      Prometheus; disabled unless AXT_METRICS_ENABLED
GET    /version      build info
```

`POST /snippets/{id}/render` resolves variables server-side and returns text. It never
executes: rendering and running are separate operations, which is what makes
"insert, review, press Enter" the default path.

## 5.11 Rate limits

| Scope | Limit |
| --- | --- |
| `POST /auth/login` | 5 / 5 min per IP; 10 / 15 min per username, then lockout |
| Session creation | 30 / min per user |
| WS ticket issue | 60 / min per user |
| Upload bytes | `AXT_UPLOAD_RATE_LIMIT` (unset = unlimited) |
| Discovery scans | 1 concurrent per user |
| Everything else | 600 / min per user, 60 burst |

In-process token buckets. Limits are configurable because a legitimate operator running a
20-host job should not be throttled by a default tuned for abuse.
