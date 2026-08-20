# Deployment, Backup, and Upgrade

Everything here assumes Docker Compose, which is the supported deployment. A single
static binary plus a systemd unit works identically; see the end of this document.

---

## 1. Install

```bash
git clone <repository-url> axt-term
cd axt-term

cp .env.example .env

# The master key encrypts every stored credential. Generate it once.
mkdir -p secrets
openssl rand -base64 32 > secrets/axt_master_key
chmod 600 secrets/axt_master_key

# Set the hostname browsers will use. Cookie security depends on this being right.
echo 'AXT_DOMAIN=axt-term.lan'            >> .env
echo 'AXT_PUBLIC_URL=https://axt-term.lan' >> .env

docker compose up -d
docker compose ps          # all three services should be healthy
```

Create the first administrator. There is deliberately no web-based signup: an
attacker who reaches the login page must not be able to mint an account.

```bash
docker compose exec axt-term axt-admin user create --username admin
```

The generated password is printed **once** and the account is flagged
must-change-password, so it has to be replaced at first login.

### Trusting the TLS certificate

Caddy issues a certificate from its own local CA, which needs no internet access.
Export the root and trust it on the machines that will use AXT-Term:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./axt-root.crt
```

To use your own certificate instead, replace `tls internal` in
`deploy/caddy/Caddyfile` with `tls /path/cert.pem /path/key.pem`.

> **Why HTTPS is not optional.** AXT-Term sets `Secure` on its session cookie and
> uses the `__Host-` prefix. Browsers refuse both over plain HTTP, so an
> `http://` deployment cannot hold a session at all. The startup banner warns
> about this explicitly rather than failing mysteriously.

---

## 2. What is stateful

| Thing | Where | Notes |
| --- | --- | --- |
| Database | `axt-data` volume, `axt-term.db` | Hosts, folders, tags, encrypted credentials, snippets, users, audit log, host-key trust store |
| Session recordings | `axt-data` volume, `recordings/` | Only when command logging is `full`. Treat as sensitive. |
| Master key | `secrets/axt_master_key` | **Not** in the volume, by design |

**Back the key up separately from the database.** A backup containing both is a
backup of your plaintext secrets, which defeats the entire encryption scheme. Losing
the key with no copy means losing every stored credential — there is no recovery
path, and that is the point.

---

## 3. Backup

`VACUUM INTO` produces a defragmented, transactionally consistent copy while the
service keeps running, so there is no maintenance window.

```bash
docker compose exec axt-term \
  axt-admin backup --out /var/lib/axt-term/backup-$(date +%F).db

docker compose cp \
  axt-term:/var/lib/axt-term/backup-$(date +%F).db ./backups/
```

Verify a backup rather than assuming it:

```bash
sqlite3 ./backups/backup-2026-08-19.db 'PRAGMA integrity_check; SELECT COUNT(*) FROM hosts;'
```

A cron entry, running as a user who can reach the Docker socket:

```cron
17 3 * * * cd /opt/axt-term && ./scripts/backup.sh >> /var/log/axt-backup.log 2>&1
```

### Restore

```bash
docker compose stop axt-term
docker compose run --rm -v "$PWD/backups:/restore" axt-term \
  sh -c 'cp /restore/backup-2026-08-19.db /var/lib/axt-term/axt-term.db'
docker compose start axt-term
```

Restore the master key that was current **when that backup was taken**. A newer key
will not open older ciphertext, and the startup canary check refuses to start
rather than presenting an apparently empty credential store.

---

## 4. Upgrade

```bash
# 1. Back up first. Migrations are forward-only and there are no down-migrations:
#    for a single-file database a verified copy is more trustworthy than a reverse
#    script that is rarely tested.
docker compose exec axt-term axt-admin backup --out /var/lib/axt-term/pre-upgrade.db
docker compose cp axt-term:/var/lib/axt-term/pre-upgrade.db ./backups/

# 2. Pull and rebuild.
git pull
docker compose build axt-term
docker compose up -d axt-term

# 3. Confirm.
docker compose logs -f axt-term | head -40
curl -sk https://axt-term.lan/readyz | jq
```

Migrations run automatically at startup, each in a transaction, each recorded with
a checksum. Two failure modes are deliberate and loud:

- **A migration changed after being applied** — startup aborts. The live schema is
  not the one this build expects, and continuing risks data loss.
- **The database contains a migration this build does not** — startup aborts. The
  binary is older than the database; upgrade the binary or restore a matching backup.

### Rotating the master key

```bash
docker compose exec axt-term axt-admin key generate > secrets/axt_master_key.new
docker compose exec axt-term axt-admin key rotate --new-key-file /run/secrets/axt_master_key_new
```

Rotation re-wraps each credential's data key; the secret ciphertext is untouched,
so it is fast and its failure window is small. The old key stays valid until you
switch `AXT_MASTER_KEY_FILE` and restart — **keep the old key until you have
confirmed the new one works.**

---

## 5. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Login appears to succeed then immediately returns to the login screen | `AXT_PUBLIC_URL` is `http://` while served over HTTPS, or vice versa. The cookie is being rejected. Match it to what the browser shows. |
| `the configured master key does not match this database` | The key changed, or a passphrase-derived key is being used against a database initialised with a raw key. Restore the original key. Do **not** delete the database to "fix" this — the data is intact and still encrypted. |
| `HOST KEY MISMATCH` on connect | Either the host was rebuilt or the connection is being intercepted. Verify the fingerprint out of band, then revoke the stored key on the Host Keys screen. There is no override in the connect path, deliberately. |
| Connection fails with `hop 1 of 2 (bastion at …)` | The named hop is the one that failed; each hop authenticates and is host-key verified independently. |
| Audit entries all show the same client address | `AXT_TRUSTED_PROXIES` does not include Caddy's network, so `X-Forwarded-For` is ignored. That is the safe default: trusting it unconditionally would let any client forge the recorded address. |
| RDP actions are disabled | `AXT_GUACD_ADDR` is unset or guacd is unreachable. `/readyz` reports it as a non-critical degraded check — a missing guacd means RDP is unavailable, not that the instance should be pulled out of service. |
| `/readyz` reports pending migrations | The container started against a newer schema than it contains. Check that the image actually rebuilt. |
| Terminal shows "Reconnecting…" repeatedly | The WebSocket cannot upgrade. Check that the reverse proxy forwards `Upgrade`/`Connection` and does not buffer — see the `@websockets` block in the Caddyfile. |
| Transfers stuck showing `interrupted` | Expected after a restart: in-flight transfers are marked retryable rather than left showing a progress bar that will never move. Click Retry. |

### Useful commands

```bash
docker compose exec axt-term axt-admin status         # counts, key version, canary check
docker compose exec axt-term axt-admin user list
docker compose logs -f axt-term
curl -sk https://axt-term.lan/readyz | jq
docker compose exec axt-term axt-admin audit prune --before 2025-01-01  # reports only
```

---

## 6. Hardening checklist

- [ ] `AXT_PUBLIC_URL` is `https://` and matches what users type
- [ ] `secrets/axt_master_key` is mode 600 and backed up **away from** the database
- [ ] `AXT_TRUSTED_PROXIES` names only the reverse proxy's network
- [ ] `AXT_SSH_HOSTKEY_POLICY=strict` once your inventory's keys are trusted
- [ ] `AXT_SSH_LEGACY_ALGOS=false` unless specific network gear requires it
- [ ] `AXT_TUNNEL_ALLOW_PUBLIC_BIND=false` — the default; a tunnel bound to `0.0.0.0` exposes an internal service
- [ ] `AXT_COMMAND_LOGGING=commands`, not `full`, unless recordings are genuinely required and protected
- [ ] Each person has their own account with the least role that works; `operator` cannot manage users or read the audit log
- [ ] Backups are restore-tested, not just taken

---

## 7. Without Docker

The binary is static and has no runtime dependencies.

```bash
make build                       # produces backend/bin/axt-term
sudo install -m 0755 backend/bin/axt-term backend/bin/axt-admin /usr/local/bin/
sudo useradd --system --home /var/lib/axt-term --shell /usr/sbin/nologin axt
sudo install -d -o axt -g axt -m 0750 /var/lib/axt-term
sudo install -m 0644 deploy/systemd/axt-term.service /etc/systemd/system/
sudo systemctl enable --now axt-term
```

RDP requires guacd separately (`apt install guacd`, or a container) with
`AXT_GUACD_ADDR` pointed at it. Everything else works without it.
