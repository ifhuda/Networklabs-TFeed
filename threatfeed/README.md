# IoC-WATCH — Threat Feed Server

A self-hosted bridge between **FortiSOAR** and **FortiGate External Resource**. Your
playbooks push indicators over a REST API; your firewalls pull a plain-text blocklist.
Everything in between — deduplication, TTL expiry, an operator dashboard, and an audit
trail — is handled for you.

Runs natively under `systemd`. **No Docker, no container runtime.**

```
FortiSOAR ──POST /api/v1/ingest (Bearer)──▶ ┌────────────────────────┐
                                            │ uvicorn + FastAPI      │
SOC operator ──HTTPS──▶ Dashboard ─────────▶│ SQLite (WAL)           │
                                            │ TTL pruner (asyncio)   │
FortiGate ──GET /api/v1/feed/fortigate─────▶└────────────────────────┘
```

---

## Why this exists

FortiSOAR can enrich and confirm indicators, but FortiGate needs them as a flat file at
a stable URL. Most teams bridge that gap with a cron job writing to a web root, which
gives you no deduplication, no expiry, and no record of who fetched what. Stale entries
accumulate silently until someone's legitimate traffic gets blocked by an IP that was a
C2 server eight months ago.

IoC-WATCH closes that loop: indicators stay in the feed only as long as your playbooks
keep confirming them, and the dashboard shows you when they stop.

## Features

- **Tolerant ingestion** — accepts six payload shapes, from FortiSOAR's nested
  `commands` structure down to a bare array of IP strings. Bad entries are reported
  per-item without failing the batch.
- **Deduplication and upsert** — one row per indicator. Re-sending updates severity,
  confidence, and comment in place.
- **TTL expiry** — indicators drop out of the feed automatically after N days without
  a refresh. Configurable globally or per external-resource object.
- **FortiGate-native output** — plain text, one entry per line. Supports IPv4, IPv6,
  CIDR, and ranges. HTTP Basic auth, ETag/`304`, and a query-string-free URL because
  FortiGate's CLI sometimes swallows `?`.
- **Operator dashboard** — dark-themed, no CDN (works on air-gapped networks). Global
  search, TLP badges, and a TTL decay strip that warns you days before coverage lapses.
- **Audit trail** — every ingest, feed pull, login, and prune, with client IP and
  duration. Tokens are recorded as SHA-256 fingerprints, never in plaintext.
- **One-command installer** — packages, service account, virtualenv, credentials,
  systemd unit, nginx, TLS, firewall rules, and a functional self-test.
- **Day-2 CLI** — `threatfeedctl` for status, diagnostics, backup, and zero-downtime
  token rotation.

## Quick start

```bash
unzip threatfeed.zip && cd threatfeed      # or: git clone && cd
sudo bash deploy/setup.sh
```

The wizard asks five questions, then prints your dashboard password, both tokens, and a
ready-to-paste FortiGate configuration block. Two to four minutes on a fresh VM.

```bash
sudo threatfeedctl doctor     # verify the install
sudo threatfeedctl feed       # see exactly what FortiGate will receive
```

Non-interactive, for Ansible or repeat deployments:

```bash
sudo bash deploy/setup.sh --yes \
  --domain feed.example.com \
  --soar-ip 10.10.10.20 \
  --fgt-ip 10.10.10.0/24 \
  --tls existing --cert /etc/ssl/certs/feed.pem --key /etc/ssl/private/feed.key \
  --comments
```

## Documentation

| Document | Contents |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Installation, TLS modes, upgrade, uninstall |
| [docs/USAGE.md](docs/USAGE.md) | FortiSOAR payloads, FortiGate configuration, CLI, dashboard |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Symptom-to-cause table drawn from real deployments |
| [docs/id/PANDUAN.md](docs/id/PANDUAN.md) | Dokumentasi lengkap (Bahasa Indonesia) |
| [docs/id/CHECKLIST-PRODUKSI.md](docs/id/CHECKLIST-PRODUKSI.md) | Runbook penerapan produksi |

## Tech stack

| Layer | Choice | Rationale |
|---|---|---|
| Runtime | Python 3.10+ / uvicorn | Single process, ~60 MB RSS, sub-second start |
| Framework | FastAPI | Pydantic validation, OpenAPI at `/api/docs` |
| Database | SQLite (WAL) | Read-heavy workload; no extra daemon, backup is one file |
| Frontend | Single HTML file | No CDN — survives isolated SOC networks |
| Process | systemd, `Type=exec` | Auto-restart, journald, kernel sandboxing |
| TLS | nginx reverse proxy | Termination, rate limiting, per-location allow-lists |

SQLite is comfortable to roughly one million indicators with a single writer. Move to
PostgreSQL if you need multiple uvicorn workers, replication, or several nodes behind a
load balancer — the `ON CONFLICT … RETURNING` syntax is identical, so only
`app/database.py` changes.

## Requirements

- Ubuntu 22.04 / 24.04 or Debian 12
- Python 3.10 or newer
- 1 vCPU, 1 GB RAM, 10 GB disk
- Correct system clock — TTL depends entirely on it

## Security notes

- `threatfeed.env` holds tokens and the dashboard password. It is mode `640`,
  `root:threatfeed`, and **must never be committed**. It is already in `.gitignore`.
- The service runs as a locked system account under a hardened systemd unit
  (`ProtectSystem=strict`, empty `CapabilityBoundingSet`). Verify with
  `systemd-analyze security threatfeed`.
- Token comparison uses `hmac.compare_digest` against every candidate, so timing does
  not leak length. Separate CIDR allow-lists gate ingestion and feed access.
- Comments from FortiSOAR are stripped of CR/LF, so a malicious comment cannot inject
  extra lines into the feed file.
- Rotate tokens without downtime: `threatfeedctl rotate ingest`, move the client over,
  then `threatfeedctl rotate ingest --finish`.

## Testing

```bash
bash tests/smoke.sh
```

Spins up a temporary instance and exercises 16 scenarios: both payload shapes, malformed
input handling, upsert-vs-insert accounting, `delete`, negative authentication, all four
feed paths, severity filtering, Basic auth, ETag/`304`, the dashboard login flow, search,
audit trail, TTL expiry plus pruning, and CRLF injection neutralisation.

## Project layout

```
app/                  FastAPI backend
  config.py           Environment-driven configuration
  database.py         SQLite WAL, schema, transaction helper
  normalize.py        FortiSOAR payload parser, IP/TLP/severity normalisation
  security.py         Bearer/Basic tokens, HMAC session cookie, CIDR allow-lists
  crud.py             Upsert-dedup, feed generator, TTL pruning, audit
  main.py             API endpoints and the pruning scheduler
static/index.html     Dashboard SPA
deploy/
  setup.sh            Installer wizard
  threatfeedctl       Day-2 operations CLI
  install.sh          Minimal installer, no nginx or wizard
  threatfeed.service  Hardened systemd unit
  nginx-threatfeed.conf
  threatfeed.env.example
tests/smoke.sh        End-to-end scenarios
```

## Compatibility

Developed and tested against FortiOS 7.4 and FortiSOAR 7.x. The feed format follows the
FortiOS External Resource specification: one entry per line, `#` for full-line comments.

Inline comments after an IP (`103.74.20.57 # C2 Server`) are available via the
`/annotated` path, but are **not** documented by Fortinet for `address`-type feeds.
Validate before relying on them — if the parser rejects them the entry count drops
silently, with no error. See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## License

MIT — see [LICENSE](LICENSE).

Not affiliated with or endorsed by Fortinet. FortiGate, FortiSOAR, and FortiOS are
trademarks of Fortinet, Inc.
