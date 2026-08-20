# Changelog

## 1.5.0

### Changed
- **"Tarik FortiSOAR" panel no longer asks for Server Address / API Key when a TAXII
  connection is already saved in Konfigurasi Sistem.** It shows a compact "connected
  to: ..." status with Test Connection and an "Ubah koneksi" toggle for ad-hoc
  overrides, instead of always rendering an editable form that duplicated what was
  already persisted. Two related bugs fixed along the way: the pull button's client-side
  validation rejected an intentionally-empty connection field (which should fall back
  to the saved config), and a successful pull could overwrite the panel's remembered
  connection with an empty string, breaking a second pull in the same session.
- **The "Pengaturan" panel has been retired.** Every one of its 15 fields duplicated
  Konfigurasi Sistem exactly, and having two places to change the same value — one
  instant, one requiring a restart — was more confusing than the restart it avoided.
  `/api/v1/settings` and `/api/v1/settings/reset` are gone (404). Values previously
  saved through Pengaturan **keep applying** after upgrading (nothing silently
  reverts) — the startup log names any leftover overrides and how to migrate them.
  New `threatfeedctl clear-legacy-settings` command removes the leftover database rows
  once migrated. See `docs/SYSTEM-CONFIG.md` for the full migration note.

## 1.4.4

### Fixed
- **FortiGate CLI snippet generator pointed `category` (URL) and `malware` (hash)
  resource types at the plain IP feed endpoint**, guaranteeing every entry would be
  rejected as invalid — confirmed against a real FortiGate GUI showing "Invalid" for
  a URL entry fed through the address/annotated endpoint. The resource path now
  follows the selected `set type`: `address`→`/api/v1/feed/fortigate`,
  `domain`→`/domain`, `malware`→`/hash`, `category`→`/url`. Snippet notes also now
  explain the correct FortiGate-side attachment for each type — hash via an
  AntiVirus profile's external malware block list, URL via a Web Filter profile as
  a Remote Category (requiring SSL deep inspection to see the URL path over HTTPS)
  — since neither attaches directly to a firewall policy the way IP/domain feeds do.

### Changed
- **`server-identity-check` in the snippet generator now defaults to `none`**
  instead of `full`. Most deployments run self-signed certificates for which
  `full` fails outright; `none` is the common case and `full` remains one click
  away for deployments with a properly chained CA certificate.

## 1.4.3

### Fixed
- **FortiOS truncated hash feed descriptions at the first non-ASCII byte,
  silently discarding the reputation label.** Confirmed via `diagnose sys
  scanunit file-hash list malware` on a production FortiGate: the em-dash
  separator used to join source and reputation (`"FortiGuard Outbreak —
  Malicious"`) is a 3-byte UTF-8 sequence, and FortiOS's malware-hash
  description parser stops at that byte, leaving only `"FortiGuard Outbreak "`
  loaded into the scanunit daemon — the hash itself still matched and blocked
  correctly, but the reason shown in logs lost all its context. Fixed at the
  source (source/reputation now joined with a plain hyphen) and, as a general
  safety net, `render_feed()` now strips any non-ASCII bytes from every
  inline comment regardless of where it originated (TAXII pull, FortiSOAR
  push, or webhook) rather than leaving line-truncation risk in one place
  and hoping no other source ever contains non-ASCII text.

## 1.4.2

### Added
- **Fourth indicator type: URL.** FortiGuard Outbreak collections mix full URLs
  (e.g. Telegram/phishing links) alongside IPs and file hashes in the same
  collection — previously unrecognised and silently miscategorised as an invalid
  domain, then dropped. Now parsed from both the STIX `[url:value = '...']` pattern
  and FortiSOAR's non-standard `indicatorTypes: ["url"]` / `typeOfFeed: "URL"`
  fields, validated with a new `normalize_url()` (requires `scheme://host`, host
  validated as domain or IP, path/query preserved as-is since URLs are
  case-sensitive beyond the host). Confirmed against the exact production payload
  (`https://t.me/ChiefYoru`, FortiGuard Outbreak, reputation=Malicious). New
  `/api/v1/feed/fortigate/url` endpoint, dashboard badge, and `ioc_type=url` filter.
- Existing databases whose `indicators` table CHECK constraint predates `'url'`
  being a valid `ioc_type` are rebuilt automatically on upgrade (SQLite can't
  ALTER a CHECK constraint in place); databases that predate `ioc_type` entirely
  are unaffected since their column was added without one.

### Fixed
- **Pagination could loop up to the full 20-page limit against a server bug.** If
  a TAXII server returns the same `next` cursor repeatedly while still reporting
  `more: true`, the puller now detects the non-advancing cursor and stops after
  confirming it (2 requests — the minimum possible to detect a repeat) instead of
  retrying the same page up to 20 times. Observed in production logs as a burst of
  identical `next=11` requests.

## 1.4.1

### Fixed
- **Critical: every production server with an existing database failed to start**
  after upgrading to 1.4.0. `CREATE INDEX ... ON indicators(ioc_type)` was part of
  the static `SCHEMA` string executed via `executescript()`, which runs *before*
  `_migrate()` gets a chance to add the `ioc_type` column via `ALTER TABLE`. On a
  fresh install this is harmless (the column already exists from `CREATE TABLE`),
  but on any server with a pre-existing database (`CREATE TABLE IF NOT EXISTS` is a
  no-op there), the index creation ran against a column that didn't exist yet and
  raised `sqlite3.OperationalError: no such column: ioc_type`, crashing the service
  on every startup attempt. The index is now created inside `_migrate()`, after the
  `ALTER TABLE`, for both the upgrade path and fresh installs. Verified against a
  real on-disk database with the pre-1.4.0 schema, including a full server startup
  and a live API request against migrated data — not just the migration function in
  isolation, which is what let this slip through in 1.4.0's testing.

## 1.5.0

### Changed
- **"Tarik FortiSOAR" panel no longer asks for Server Address / API Key when a TAXII
  connection is already saved in Konfigurasi Sistem.** It shows a compact "connected
  to: ..." status with Test Connection and an "Ubah koneksi" toggle for ad-hoc
  overrides, instead of always rendering an editable form that duplicated what was
  already persisted. Two related bugs fixed along the way: the pull button's client-side
  validation rejected an intentionally-empty connection field (which should fall back
  to the saved config), and a successful pull could overwrite the panel's remembered
  connection with an empty string, breaking a second pull in the same session.
- **The "Pengaturan" panel has been retired.** Every one of its 15 fields duplicated
  Konfigurasi Sistem exactly, and having two places to change the same value — one
  instant, one requiring a restart — was more confusing than the restart it avoided.
  `/api/v1/settings` and `/api/v1/settings/reset` are gone (404). Values previously
  saved through Pengaturan **keep applying** after upgrading (nothing silently
  reverts) — the startup log names any leftover overrides and how to migrate them.
  New `threatfeedctl clear-legacy-settings` command removes the leftover database rows
  once migrated. See `docs/SYSTEM-CONFIG.md` for the full migration note.

## 1.4.4

### Fixed
- **FortiGate CLI snippet generator pointed `category` (URL) and `malware` (hash)
  resource types at the plain IP feed endpoint**, guaranteeing every entry would be
  rejected as invalid — confirmed against a real FortiGate GUI showing "Invalid" for
  a URL entry fed through the address/annotated endpoint. The resource path now
  follows the selected `set type`: `address`→`/api/v1/feed/fortigate`,
  `domain`→`/domain`, `malware`→`/hash`, `category`→`/url`. Snippet notes also now
  explain the correct FortiGate-side attachment for each type — hash via an
  AntiVirus profile's external malware block list, URL via a Web Filter profile as
  a Remote Category (requiring SSL deep inspection to see the URL path over HTTPS)
  — since neither attaches directly to a firewall policy the way IP/domain feeds do.

### Changed
- **`server-identity-check` in the snippet generator now defaults to `none`**
  instead of `full`. Most deployments run self-signed certificates for which
  `full` fails outright; `none` is the common case and `full` remains one click
  away for deployments with a properly chained CA certificate.

## 1.4.3

### Fixed
- **FortiOS truncated hash feed descriptions at the first non-ASCII byte,
  silently discarding the reputation label.** Confirmed via `diagnose sys
  scanunit file-hash list malware` on a production FortiGate: the em-dash
  separator used to join source and reputation (`"FortiGuard Outbreak —
  Malicious"`) is a 3-byte UTF-8 sequence, and FortiOS's malware-hash
  description parser stops at that byte, leaving only `"FortiGuard Outbreak "`
  loaded into the scanunit daemon — the hash itself still matched and blocked
  correctly, but the reason shown in logs lost all its context. Fixed at the
  source (source/reputation now joined with a plain hyphen) and, as a general
  safety net, `render_feed()` now strips any non-ASCII bytes from every
  inline comment regardless of where it originated (TAXII pull, FortiSOAR
  push, or webhook) rather than leaving line-truncation risk in one place
  and hoping no other source ever contains non-ASCII text.

## 1.4.2

### Added
- **Fourth indicator type: URL.** FortiGuard Outbreak collections mix full URLs
  (e.g. Telegram/phishing links) alongside IPs and file hashes in the same
  collection — previously unrecognised and silently miscategorised as an invalid
  domain, then dropped. Now parsed from both the STIX `[url:value = '...']` pattern
  and FortiSOAR's non-standard `indicatorTypes: ["url"]` / `typeOfFeed: "URL"`
  fields, validated with a new `normalize_url()` (requires `scheme://host`, host
  validated as domain or IP, path/query preserved as-is since URLs are
  case-sensitive beyond the host). Confirmed against the exact production payload
  (`https://t.me/ChiefYoru`, FortiGuard Outbreak, reputation=Malicious). New
  `/api/v1/feed/fortigate/url` endpoint, dashboard badge, and `ioc_type=url` filter.
- Existing databases whose `indicators` table CHECK constraint predates `'url'`
  being a valid `ioc_type` are rebuilt automatically on upgrade (SQLite can't
  ALTER a CHECK constraint in place); databases that predate `ioc_type` entirely
  are unaffected since their column was added without one.

### Fixed
- **Pagination could loop up to the full 20-page limit against a server bug.** If
  a TAXII server returns the same `next` cursor repeatedly while still reporting
  `more: true`, the puller now detects the non-advancing cursor and stops after
  confirming it (2 requests — the minimum possible to detect a repeat) instead of
  retrying the same page up to 20 times. Observed in production logs as a burst of
  identical `next=11` requests.

## 1.4.1

### Added
- **"Tarik ulang semua" option in the FortiSOAR pull panel** (`full_history`). The
  `added_after` cursor only returns objects newly *added* to a TAXII collection, not
  ones whose fields changed after being added — if FortiSOAR updates an existing
  indicator's reputation, TLP, or confidence without bumping its "date added", a
  routine incremental pull will never see that change again. Checking this box (or
  sending `full_history: true` via the API) bypasses the cursor and re-pulls the
  whole collection, so field-level updates on already-known indicators land as
  upserts. Resets to unchecked after a successful pull so it isn't left on by
  accident.

## 1.4.0

### Added
- **Multi-type indicator support: IP, domain, and file hash.** Previously the TAXII
  puller only recognised IP addresses; domain-name and file-hash objects (common in
  FortiGuard Outbreak and Phishing Threat Feeds collections) were silently skipped.
  A new `ioc_type` column (`ip`/`domain`/`hash`) tracks what kind of indicator each
  row is, populated from STIX `pattern` fields (`domain-name:value`,
  `file:hashes.'SHA-256'`, etc.) or FortiSOAR's `indicatorTypes`/`typeOfFeed` fields.
  New `normalize_domain()` and `normalize_hash()` validate each type on the way in.
  Existing databases are migrated automatically on upgrade (`ioc_type` defaults to
  `'ip'` for all pre-existing rows).
- **Dashboard: Tipe column and filter, separate from Reputasi.** The old "Type" column
  (which showed FortiSOAR's `reputation` text, e.g. "Malicious") is now labelled
  **Reputasi**. A new **Tipe** column and dropdown filter show the indicator kind
  (IP Address / Domain / Hash) as a coloured badge — the two were previously
  conflated under one "Type" label.
- **Feed FortiGate split by type.** `/api/v1/feed/fortigate` now serves IP addresses
  only (locked server-side, not overridable by query string — mixing types into a
  live `set type address` external-resource would silently break it). Two new
  endpoints: `/api/v1/feed/fortigate/domain` for `set type domain`, and
  `/api/v1/feed/fortigate/hash` for hash-consuming integrations (FortiOS support for
  hash-type external-resources varies by version).
- `/api/v1/indicators`, the export endpoints, and `/api/v1/admin/soar/pull-now`'s
  underlying storage layer all support filtering and reporting on `ioc_type`.

## 1.3.3

### Fixed
- **Critical: a single non-IP object in a TAXII collection crashed the entire pull
  cycle with a 500 error**, instead of being skipped like other non-IP objects.
  FortiGuard Outbreak collections routinely mix IPv4 indicators with file-hash
  indicators (`typeOfFeed: "FileHash-SHA256"`) in the same collection; the hash
  string reached `normalize_ip`, which raised a raw `ValueError` from Python's
  `ipaddress` module that only `NormalizeError` was being caught for. Confirmed
  against the exact production traceback and payload. Every mixed IP+hash
  collection was previously unpullable in its entirety, regardless of how many
  valid IPs it also contained.
- Root-caused in `normalize_ip` itself (`app/normalize.py`), not just patched at the
  TAXII call site: the function is documented to always raise `NormalizeError` for
  invalid input, but its final branch (and, less commonly, its range-parsing branch)
  could leak a bare `ValueError`. Every call site across the codebase already
  followed the "catch `NormalizeError`" convention; this was the one place that
  didn't hold. Now genuinely never leaks `ValueError` — confirmed with malformed
  ranges, malformed CIDR, and non-IP strings — while preserving the specific
  "range terbalik" / "range campur IPv4/IPv6" messages that also raise
  `NormalizeError` internally.

## 1.3.2

### Changed
- **Severity from FortiSOAR TAXII pulls now maps to the standard Critical/High/
  Medium/Low/Info scale**, instead of copying the raw `reputation` text (which
  previously produced non-standard values like "Malicious" in the Severity column).
  `Malicious`→Critical, `Suspicious`→High, `Unknown`→Medium, known-clean values
  (`Known Good`/`Benign`/`Clean`/`Trusted`/`Safe`/`Whitelisted`)→Info, anything
  unrecognised→Medium. Type still shows the raw `reputation` text as before — only
  Severity is normalised, so the original FortiSOAR label stays visible while
  Severity becomes comparable across every other source in the dashboard.

## 1.3.1

### Fixed
- **Field mapping for FortiSOAR's actual TAXII payload.** The Outgoing TAXII Feed does
  not send standard STIX 2.1 — it sends FortiSOAR's own `ThreatIntel` shape, with
  `reputation`, `source`, and `tLP` (capital L) as direct object fields, while
  `pattern` and `labels` are always empty. Treating it as standard STIX left every
  pulled indicator with `type=Indicator`, `comment=<the IP itself>` (from the `name`
  field), and `source=<local feed name>` instead of the real intel source. Now mapped
  correctly: Type and Severity from `reputation`, Source from `source`, Comment as
  `source — reputation`, TLP from `tLP`. Confirmed against real payloads from
  production `curl` output. Servers sending genuine STIX 2.1 still fall back to
  `labels`/`x_severity`/`x_tlp` as before.

## 1.3.0

### Added
- **Multiple TAXII collections at once.** `TF_SOAR_TAXII_COLLECTION_ID` now accepts a
  comma-separated list. Each collection tracks its own `added_after` cursor from the
  audit trail, so adding a collection never disturbs another's schedule, and one
  collection failing never blocks the rest on the same poll cycle. The "Tarik
  FortiSOAR" panel is now a checklist (was a single-select dropdown): tick any number
  of collections and pull them together, with a per-collection ✓/✗ result.
- `/api/v1/admin/soar/pull-now` accepts `collection_ids` (array); aggregates totals
  while reporting each collection's own result, and only fails the whole request if
  every collection in the batch failed.
- `/api/v1/admin/soar/status` accepts `?ids=` so the panel can show pull status for
  collections that are only being tested ad hoc — not yet saved to `.env`.

### Fixed
- The status panel previously only reported pull results for collections already
  saved to `.env`; a collection just pulled via the on-demand panel showed "never
  pulled" even immediately after a successful pull.

## 1.2.0

### Added
- **Pull from FortiSOAR via TAXII 2.1** (`app/taxii_client.py`), complementing the
  existing push ingest. New "Tarik FortiSOAR" panel: test a connection, browse
  collections, and pull on demand — all before anything is saved to `.env`. Scheduled
  automatic polling via `TF_SOAR_TAXII_ENABLED` and related config, on its own asyncio
  task independent of the TTL pruner so a slow FortiSOAR server never delays it.
  Parses STIX `pattern` fields and falls back to FortiSOAR's non-standard raw `value`
  field when present. Cursor (`added_after`) is tracked per collection from the audit
  trail, not globally, so testing one collection never skips indicators in another.

## 1.1.0

### Fixed
- `TF_BACKUP_DIR` left blank in `.env` (`TF_BACKUP_DIR=`) resolved to the current
  working directory instead of the data directory, so scheduled backups wrote to the
  wrong place and the restore panel showed it as empty. `--upgrade` now self-heals
  existing installs; the shipped `.env` example no longer leaves this blank
- Two different empty-string-handling bugs for the same variable existed in
  `app/config.py` and `app/backup.py` — one was correct, one wasn't. Unified

### Changed
- **System Configuration page and database restore are now enabled by default.**
  Previously opt-in via `--enable-env-editor`; a plain `sudo bash deploy/setup.sh
  --upgrade` now installs both root helpers and turns `TF_ALLOW_ENV_WRITE=true` on.
  `--enable-env-editor` still works as a backward-compatible alias. To keep the old
  opt-in behaviour, use `--disable-env-editor`

## 1.0.0

First public release.

### Features
- Ingestion API accepting six FortiSOAR payload shapes, with per-entry error reporting
- Deduplicating upsert keyed on `ip_address`
- TTL expiry enforced at both read time and by a background pruner
- Four feed paths, including query-string-free variants for FortiGate's CLI
- Selectable inline comment format: `plain`, `short`, `full`
- Dashboard with TTL decay strip, global search, and TLP badges; no CDN dependency
- Audit trail covering ingest, feed pull, login, delete, and prune
- ETag / `304 Not Modified` support for feed pulls
- Settings panel in the dashboard: fifteen policy settings editable at runtime with no
  restart, stored as database overrides on top of `.env`. Secrets stay file-only
- `setup.sh` installer wizard and `threatfeedctl` operations CLI
- Third-party webhook support: `/ingest/block` and `/ingest/unblock` paths, opt-in
  `?deep=true` JSON scanning with attacker-field preference, query-string metadata
  overrides, and an `/ingest/echo` endpoint for inspecting unknown payloads

- System Configuration page: edits all 24 `.env` variables from the browser via a
  root helper invoked through one narrow sudoers rule. Opt-in (`TF_ALLOW_ENV_WRITE`),
  requires password re-entry, backs up before writing, and schedules the restart with
  `systemd-run` so the HTTP response completes first

- `TF_FEED_USERNAME`: optional HTTP Basic username enforcement for FortiGate feed pulls,
  editable from the GUI. Empty by default, so existing installs are unaffected
- FortiGate CLI snippet generator in the admin page, with masked token, audit-logged
  reveal, a live count of matching indicators, and a copyable `curl` test command
- `type=` filter on the feed endpoint; all value filters are now case-insensitive
- Automatic backups on a schedule with rotation, plus restore from the Backup page —
  from a stored snapshot or an uploaded file. Candidates are validated before anything is
  touched, a pre-restore snapshot is always taken, and the helper rolls back if the
  service will not start on the restored database
- Export from the dashboard: indicators as CSV/JSON following the active filters, audit
  trail export, and a streamed SQLite snapshot download. CSV output is neutralised
  against spreadsheet formula injection

- Automatic backups on a configurable interval with count-based rotation, plus a
  Backup panel in the dashboard: create, download, delete, and restore
- Restore from a server-side snapshot or an uploaded `.db`, guarded by file validation,
  a pre-restore snapshot, and password confirmation; the swap runs in a root helper via
  a systemd path unit

### Notes
- SQLite with a single writer; `--workers 1` is deliberate
- Inline feed comments are undocumented in FortiOS for `address`-type feeds — validate
  the entry count before relying on them in production
- The System Configuration page widens the blast radius of a hijacked dashboard session
  from policy changes to credential changes. It ships disabled for that reason
