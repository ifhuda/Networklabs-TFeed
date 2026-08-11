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

`username`/`password` are sent as HTTP Basic; the server checks the **password** against
`TF_FEED_TOKENS`, so the username can be anything. Use `server-identity-check none`
while the certificate is self-signed.

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
| `tlp=` | all | `tlp=TLP:RED,TLP:AMBER` |
| `feed_name=` | all | Restrict to one FortiSOAR feed |
| `min_confidence=` | `TF_FEED_MIN_CONFIDENCE` | e.g. `min_confidence=80` |
| `ttl_days=` | `TF_TTL_DAYS` | Per-resource TTL override |
| `limit=` | 131072 | FortiOS hard limit |

Several external-resource objects can share one server:

```
edit "IoC-CRITICAL"  set resource "https://…/feed/fortigate?severity=Malicious,Critical"
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

## Configuration reference

`/etc/threatfeed/threatfeed.env` — restart the service after any change.

| Key | Default | Meaning |
|---|---|---|
| `TF_TTL_DAYS` | `30` | Days before an unrefreshed indicator leaves the feed. `0` = never |
| `TF_HARD_DELETE_DAYS` | `0` | Permanently delete expired rows after N days. `0` = never |
| `TF_INGEST_TOKENS` | — | Comma-separated; multiple values enable zero-downtime rotation |
| `TF_FEED_TOKENS` | — | Same, for FortiGate. Empty means the feed is public |
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
