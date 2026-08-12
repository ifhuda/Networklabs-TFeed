# Changelog

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
- Export from the dashboard: indicators as CSV/JSON following the active filters, audit
  trail export, and a streamed SQLite snapshot download. CSV output is neutralised
  against spreadsheet formula injection

### Notes
- SQLite with a single writer; `--workers 1` is deliberate
- Inline feed comments are undocumented in FortiOS for `address`-type feeds — validate
  the entry count before relying on them in production
- The System Configuration page widens the blast radius of a hijacked dashboard session
  from policy changes to credential changes. It ships disabled for that reason
