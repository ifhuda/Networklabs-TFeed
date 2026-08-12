# Usage

## FortiSOAR — pushing indicators

**Endpoint:** `POST https://<server>/api/v1/ingest`
**Headers:** `Authorization: Bearer <TF_INGEST_TOKENS>`, `Content-Type: application/json`

The HTTP method is always `POST`. Adding, deleting, and replacing are distinguished by
the `command` field in the body, not by the HTTP verb — sending `DELETE` returns
`405 Method Not Allowed`.

### Payload shapes

The parser accepts six forms, so you don't have to normalise your playbooks:

```jsonc
// 1. Full FortiSOAR structure
{"commands":[{"name":"Threat_Feeds-IP-01","command":"add","entries":[
  {"ip":"103.74.20.57","type":"Malware","severity":"Malicious","confidence":100,
   "tlp":"TLP:RED","source":"FortiSOAR Playbook","comment":"C2 server confirmed"}]}]}

// 2. Single command, no wrapper
{"name":"feed-01","command":"add","entries":[{"ip":"1.2.3.4"}]}

// 3. Array of strings
{"entries":["103.74.20.57","45.155.205.233"]}

// 4. Bare array
["103.74.20.57","45.155.205.233"]

// 5. Mixed objects and strings
{"entries":["1.2.3.4",{"ip":"5.6.7.8","severity":"High"}]}

// 6. Single object
{"ip":"103.74.20.57","severity":"Malicious"}
```

The IP is read from whichever of these keys is present: `ip`, `ip_address`, `value`,
`indicator`, `address`, `src_ip`, `dst_ip`. FortiSOAR's TAXII module puts indicators in
`value`, so its output works unchanged.

### Commands

| `command` | Effect |
|---|---|
| `add` / `update` | Upsert. New IP inserts; existing IP updates `severity`, `confidence`, `tlp`, `comment`, `updated_at`, and increments `hit_count` |
| `delete` / `remove` | Sets `status='revoked'`. Drops out of the feed immediately; the row and its history remain |
| `replace` / `sync` | Full reconciliation. Entries you send are upserted; everything else in that named feed is revoked |

Use `replace` when a playbook produces the complete current list each run — the server
works out what to withdraw, scoped to that feed name alone.

Deleting a FortiSOAR-sourced indicator:

```json
{"commands":[{"name":"Threat_Feeds-IP-01","command":"delete",
  "entries":[{"ip":"{{ vars.input.params.sourceIp }}"}]}]}
```

Only `ip` is read for deletions; other fields can be omitted.

### Normalisation

Applied automatically so playbook output doesn't need cleaning up:

| Input | Stored as |
|---|---|
| `"40%"` | `40` |
| `tlp:green`, `TLP-GREEN`, `green` | `TLP:GREEN` |
| `TLP:CLEAR` | `TLP:WHITE` |
| `critical`, `malicious` | `Critical`, `Malicious` |
| `1.2.3.4/32` | `1.2.3.4` |
| `10.0.0.1-10.0.0.9` | kept as a range |
| loopback, multicast, unspecified | rejected with a reason |
| CR/LF inside a comment | stripped |

### Response

```json
{"status":"partial","received":5,"inserted":2,"updated":1,"deduplicated":1,
 "revoked":0,"rejected":1,"errors":[{"entry":"999.1.1.1","error":"…"}],
 "processed_at":"2026-08-11T05:24:37Z"}
```

`status` is `ok` or `partial`. A bad entry never fails the batch — the playbook still
succeeds, and `errors` tells you which lines to fix.

---

## FortiGate — consuming the feed

```
config system external-resource
    edit "IoC-WATCH-Blocklist"
        set type address
        set resource "https://<server>/api/v1/feed/fortigate"
        set refresh-rate 5
        set server-identity-check full
        set username "fortigate"
        set password <TF_FEED_TOKENS>
        set status enable
    next
end
```

`username`/`password` are sent as HTTP Basic.

**The username.** By default `TF_FEED_USERNAME` is empty and only the password is
checked, so any username works — that is the historical behaviour and it stays the
default so upgrades don't break running installs. Set `TF_FEED_USERNAME` (Konfigurasi
Sistem → Kredensial & Keamanan) to require an exact match:

| `TF_FEED_USERNAME` | FortiGate sends | Result |
|---|---|---|
| empty | any username | accepted |
| `fortigate` | `fortigate` | accepted |
| `fortigate` | anything else | `401 Username feed tidak cocok` |

Bearer tokens and `?token=` carry no username, so they are unaffected — forcing one
there would break legitimate integrations without adding security, since the token is
the secret either way.

Setting a username after FortiGate is already pulling will break the feed until
`set username` on the firewall matches. Change both together.

Use `server-identity-check none` while the certificate is self-signed.

### CLI snippet generator

Konfigurasi Sistem → Kredensial & Keamanan has a **Snippet CLI FortiGate** panel that
assembles the block above from live configuration: the base URL comes from the request
you are making (the address proven reachable, not a guess from the hostname), the path
follows `TF_FEED_INLINE_COMMENTS`, and the username follows `TF_FEED_USERNAME`. Object name, `set type`, `server-identity-check`, `refresh-rate`, and optional
`severity` / `type` / `tlp` / `feed_name` filters are adjustable inline.

The header shows **how many indicators actually match** the current filters, updating as
you type. Zero turns red and adds an explicit warning — a mistyped filter produces an
empty feed that FortiGate accepts without complaint.

**`set type`** is selectable: `address` (the default and the only one that matches what
this server produces), `domain`, `malware`, `mac-address`, and `category`. Choosing
anything other than `address` raises a warning, because the feed emits IP addresses and
FortiGate would be expecting domains, hashes, MAC addresses, or a URL list — the entries
would be rejected. Picking `category` reveals a category-number field; FortiOS requires
one in the 192–221 range reserved for user-defined categories, and the generator adds the
matching `set category` line.

The token renders as `<TOKEN_FEED>` until you press **Tampilkan token**; revealing it is
recorded in the audit trail as `feed_token_revealed`. **Salin perintah uji curl** copies
an equivalent `curl -u` command for testing from the FortiGate side.

The panel also warns about conditions worth knowing before you paste: an empty username
policy, `identity-check none`, inline comments needing entry-count validation, and an
empty feed allow-list.

Applying it to a policy:

```
config firewall policy
    edit 0
        set name "Block-IoC-WATCH"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "IoC-WATCH-Blocklist"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
```

Verification on FortiGate:

```
diagnose sys external-resource list
diagnose sys external-resource entry-list IoC-WATCH-Blocklist
```

If `diagnose test application externalresource` returns a parse error, the daemon name
differs on your build — toggle `set status disable` then `enable` instead, which forces
a refresh on every version.

### Feed paths

FortiGate's CLI sometimes swallows `?` when `set resource` is typed directly, turning a
parameterised URL into a nonexistent path that answers `404` — reported in the GUI as
`Server not reachable`. Query-string-free paths avoid the whole problem:

```
/api/v1/feed/fortigate            follows TF_FEED_INLINE_COMMENTS (default: bare IPs)
/api/v1/feed/fortigate/clean      always bare IPs
/api/v1/feed/fortigate.txt        always bare IPs, for tools that expect an extension
/api/v1/feed/fortigate/annotated  always with inline comments
```

### Query parameters

| Parameter | Default | Effect |
|---|---|---|
| `comments=true` | `TF_FEED_INLINE_COMMENTS` | Force comments on or off |
| `severity=` | all | `severity=Malicious,Critical` |
| `type=` | all | Indicator type: `type=Deception,Malware` |
| `tlp=` | all | `tlp=TLP:RED,TLP:AMBER` |
| `feed_name=` | all | Restrict to one FortiSOAR feed |
| `min_confidence=` | `TF_FEED_MIN_CONFIDENCE` | e.g. `min_confidence=80` |
| `ttl_days=` | `TF_TTL_DAYS` | Per-resource TTL override |
| `limit=` | 131072 | FortiOS hard limit |

All four value filters (`severity`, `type`, `tlp`, `feed_name`) are **case-insensitive**,
so `?severity=high` and `?severity=High` behave identically. Stored values are normalised
to Title Case, and a case-sensitive match would have returned an empty feed with no error
at all — a blocklist that silently empties is a failure you only notice after something
gets through.

Several external-resource objects can share one server:

```
edit "IoC-CRITICAL"  set resource "https://…/feed/fortigate?severity=malicious,critical"
edit "IoC-DECEPTION" set resource "https://…/feed/fortigate?type=deception"
edit "IoC-TOR"       set resource "https://…/feed/fortigate?feed_name=Tor-Exit-Nodes"
```

FortiOS caps each file at 10 MB or 131,072 entries, whichever comes first, and limits
how many `system.external-resource` objects a model supports.

### Comments in the feed

```
sudo threatfeedctl config     # TF_FEED_COMMENT_FORMAT
```

| Value | Output |
|---|---|
| `plain` (default) | `103.74.20.57 # C2 server confirmed` — the `comment` column only |
| `short` | `103.74.20.57 # Malware \| C2 server confirmed` |
| `full` | `103.74.20.57 # Malware \| Malicious/100 \| TLP:RED \| FortiSOAR \| C2 server confirmed` |

Entries without a comment are written as a bare IP, with no trailing `#`.

> **Validate before relying on this.** FortiOS documents full-line `#` comments, but
> **not** inline comments after an IP for `address`-type feeds. If your parser rejects
> them, the symptom is a silently reduced entry count, not an error. Compare:
>
> ```
> diagnose sys external-resource entry-list IoC-WATCH-Blocklist
> ```
> ```bash
> sudo threatfeedctl feed | grep -c .
> ```
>
> The two numbers must match. If they don't, switch to `/clean` — per-IP context is
> still available in the dashboard and via `threatfeedctl search`.

---

## Dashboard

`https://<server>/` — log in with `TF_ADMIN_PASSWORD`. The session lives in an
HttpOnly, HMAC-signed cookie; no browser storage is used.

**TTL decay strip.** Each bar is one day of age since an indicator was last refreshed,
coloured by severity, with the expiry cliff marked at day `TF_TTL_DAYS`. Bars piling up
on the right mean FortiSOAR has stopped refreshing older indicators — a warning several
days before coverage lapses, rather than after.

**Stat cards.** Total indicators, how many are actually served to FortiGate, last sync
time, and FortiGate pull count over 24 hours.

**Table.** Severity is a heat bar sized by confidence; TLP is a badge in its official
colour. Every column sorts. One search box covers IP, type, TLP, severity, source,
comment, and feed name, plus five dropdown filters.

**Audit trail.** The last 60 events with client IP and duration.

### Export

The **Ekspor** button in the toolbar offers five downloads:

| Item | Contents |
|---|---|
| Indikator CSV | Every column, **honouring the filters currently applied to the table** |
| Indikator JSON | Same rows as an array of objects, for re-processing |
| Audit CSV / JSON | The last 5,000 audit events |
| Backup penuh (.db) | A consistent SQLite snapshot of the whole database |

The indicator exports reuse exactly the same query as the table, so "export what I am
looking at" means precisely that — the menu shows the matching row count before you
click.

Exports stream in chunks rather than being assembled in memory: 130,000 indicators held
as one string would be tens of megabytes inside a service capped at `MemoryMax=1G`.

**CSV values are neutralised against formula injection.** Excel and LibreOffice execute
cells beginning with `=`, `+`, `-`, or `@`, and the `comment` column is filled by
FortiSOAR and third-party webhooks — content you did not write. A single
`=HYPERLINK(...)` comment would otherwise attack the analyst who opens the export, so
such values are prefixed with a single quote and treated as text.

**The backup file contains everything** — indicators, the full audit trail including
client IP addresses, and settings overrides. Treat it as a production backup: store it
encrypted, and do not send it over unprotected channels. It uses SQLite's `backup` API,
so it is safe to take while the service is running, unlike `cp`.

### Backup & restore

The **Backup** button opens a panel listing every snapshot on the server, with size,
timestamp, and whether it was taken automatically or just before a restore.

**Automatic backups** run on the same loop as TTL pruning. The schedule is computed from
the last backup's timestamp rather than from process start, so a service that restarts
often still gets one snapshot per interval instead of one per restart.

| Setting | Default | Meaning |
|---|---|---|
| `TF_BACKUP_ENABLED` | `true` | Turn the scheduler on or off |
| `TF_BACKUP_INTERVAL_HOURS` | `24` | How often a snapshot is taken |
| `TF_BACKUP_KEEP` | `14` | Older snapshots are deleted beyond this count |
| `TF_BACKUP_DIR` | `<db dir>/backups` | Must be writable by the service account |

All four are editable from Konfigurasi Sistem.

**Restoring** replaces the entire database. Two things happen first: the file is
validated as a genuine IoC-WATCH database — SQLite header, `quick_check`, required
tables and columns — and a snapshot of the current state is taken and kept as
`…-pre-restore.db`. You are then asked for the dashboard password.

You can restore from a snapshot on the server, or drag a `.db` file onto the panel.
Uploaded files are inspected before anything changes: an invalid file is rejected with a
reason and nothing is touched.

The swap itself is done by a root helper (`threatfeed-restore-db`) triggered through a
systemd path unit, the same pattern as the `.env` editor. The service must be stopped
before its database file is replaced — swapping a file underneath a live SQLite
connection leaves the old `-wal` journal pointing at the wrong database — and the
application has no privilege to stop itself. Install it with:

```bash
sudo bash deploy/setup.sh --upgrade --enable-env-editor
```

Without the helper, backups still work; only the Restore button is unavailable, and the
panel says so. The CLI path stays open either way:

```bash
sudo threatfeedctl restore /var/lib/threatfeed/backups/threatfeed-….db
```

The equivalent from the CLI:

```bash
sudo threatfeedctl backup                 # to /var/backups/threatfeed/
sudo threatfeedctl search "" > out.txt    # ad-hoc queries
```

The page refreshes itself every 30 seconds.

---

## `threatfeedctl`

Installed to `/usr/local/bin/` by `setup.sh`. Most subcommands need `sudo`, because
`/etc/threatfeed` is mode 750 and database queries run as the service account.

```bash
sudo threatfeedctl doctor            # ten common failure points, with hints
sudo threatfeedctl status            # service, database, feed size, recent activity
sudo threatfeedctl creds             # dashboard URL, password, both tokens
sudo threatfeedctl feed 25           # exactly what FortiGate receives
sudo threatfeedctl test 1.2.3.4      # push a test IoC through the FortiSOAR path
sudo threatfeedctl expire 1.2.3.4    # withdraw one IP from the feed
sudo threatfeedctl search C2         # query the database
sudo threatfeedctl stats             # counts by severity, TLP, source
sudo threatfeedctl audit 20          # recent audit entries
sudo threatfeedctl prune             # run TTL pruning now
sudo threatfeedctl backup            # safe while the service runs
sudo threatfeedctl restore <file>
sudo threatfeedctl config            # edit .env, then restart
threatfeedctl logs -f                # journalctl follow
```

### Token rotation

Two stages, so there is no service gap:

```bash
sudo threatfeedctl rotate ingest             # new and old token both valid
# … point FortiSOAR at the new token …
sudo threatfeedctl rotate ingest --finish    # revoke the old one
```

`rotate feed` works the same way for FortiGate. `rotate admin` regenerates the dashboard
password immediately.

---

## Configuration

### From the dashboard

Click **Pengaturan** in the header. Fifteen policy settings can be changed there, and
they take effect immediately — no restart:

| Group | Settings |
|---|---|
| Feed policy | TTL, hard-delete window, minimum confidence, entry cap |
| Feed format | Inline comments on/off, comment format |
| Entry defaults | Type, severity, TLP, source, confidence |
| Access control | Ingest and feed CIDR allow-lists |
| Maintenance | Prune interval, audit retention |

Changes are stored as overrides in the database, not written back to the `.env` file,
and each field shows whether its current value comes from `.env` or the dashboard.
**Kembalikan ke .env** discards every override at once.

Two safeguards are built in. Loopback entries are always re-added to the CIDR allow-lists,
so a typo cannot lock out `threatfeedctl`, which reaches the API over `127.0.0.1`. And
tokens, the dashboard password, the session key, the database path, and the proxy flags
are deliberately **not** editable from the web interface — otherwise a hijacked dashboard
session would escalate into full control. Those stay in `.env`, changeable only by root:

```bash
sudo threatfeedctl config
sudo threatfeedctl rotate ingest|feed|admin
```

The service reads `.env` as the service account, which has no write access to it. That
is why overrides live in the database: a network-facing process should not be able to
rewrite its own credentials.

### From the file

`/etc/threatfeed/threatfeed.env` — restart the service after any change. Values here are
the baseline; dashboard overrides sit on top of them.

| Key | Default | Meaning |
|---|---|---|
| `TF_TTL_DAYS` | `30` | Days before an unrefreshed indicator leaves the feed. `0` = never |
| `TF_HARD_DELETE_DAYS` | `0` | Permanently delete expired rows after N days. `0` = never |
| `TF_INGEST_TOKENS` | — | Comma-separated; multiple values enable zero-downtime rotation |
| `TF_FEED_TOKENS` | — | Same, for FortiGate. Empty means the feed is public |
| `TF_FEED_USERNAME` | empty | Required HTTP Basic username. Empty = any username accepted |
| `TF_ADMIN_PASSWORD` | — | Dashboard login |
| `TF_SECRET_KEY` | random | Session cookie HMAC key. **Set a fixed value** or sessions break on restart |
| `TF_INGEST_ALLOWED_CIDRS` | empty | Allow-list for ingestion. Empty = all. Keep loopback |
| `TF_FEED_ALLOWED_CIDRS` | empty | Allow-list for the feed. Empty = all. Keep loopback |
| `TF_COOKIE_SECURE` | `true` | Set `false` only for plain-HTTP labs |
| `TF_FEED_INLINE_COMMENTS` | `false` | Default for the base feed path |
| `TF_FEED_COMMENT_FORMAT` | `plain` | `plain`, `short`, or `full` |
| `TF_FEED_MIN_CONFIDENCE` | `0` | Minimum confidence to appear in the feed |
| `TF_TRUST_PROXY` | `true` | Read `X-Forwarded-For` from nginx |
| `TF_AUDIT_RETENTION_DAYS` | `90` | Audit log retention |

Populate the allow-lists from what the server actually observes, not from assumption:

```bash
sudo threatfeedctl audit 10
```

The Client column shows the real post-NAT address.

---

## API reference

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/ingest` | Bearer (ingest) | Push indicators |
| `GET` | `/api/v1/feed/fortigate` | Bearer / Basic / `?token=` | Plain-text feed |
| `GET` | `/api/v1/feed/stats` | same as feed | Entry count |
| `POST` | `/api/v1/auth/login` | password | Issue session cookie |
| `GET` | `/api/v1/stats` | cookie | Dashboard statistics |
| `GET` | `/api/v1/indicators` | cookie | Search, filter, sort, paginate |
| `GET` | `/api/v1/filters` | cookie | Distinct values for dropdowns |
| `DELETE` | `/api/v1/indicators/{id}` | cookie | Delete one indicator permanently |
| `GET` | `/api/v1/audit` | cookie | Audit trail |
| `POST` | `/api/v1/maintenance/prune` | cookie | Manual pruning |
| `GET` | `/healthz` | — | Health check |
| `GET` | `/api/docs` | — | OpenAPI schema |

`/api/docs` exposes the schema, not data. Block it in nginx if your policy requires:

```nginx
location /api/docs { deny all; }
```
