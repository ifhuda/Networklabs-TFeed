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
- `setup.sh` installer wizard and `threatfeedctl` operations CLI

### Notes
- SQLite with a single writer; `--workers 1` is deliberate
- Inline feed comments are undocumented in FortiOS for `address`-type feeds — validate
  the entry count before relying on them in production
