# Integrating third-party webhooks

FortiSOAR pushes a payload you control. Other products — FortiDeceptor's
**Integrate With New Device**, SIEM alert actions, ticketing hooks — send a fixed
payload you cannot shape, and often distinguish *block* from *unblock* only by which
URL they call.

Three features cover that case:

| Feature | Purpose |
|---|---|
| Path-based commands | `/api/v1/ingest/block` and `/api/v1/ingest/unblock` — action comes from the URL, not the body |
| `?deep=true` | Scan the whole JSON tree for IP addresses instead of expecting known field names |
| Query-string metadata | Set `source`, `type`, `severity`, `tlp`, `confidence`, `feed_name`, `comment` from the URL |

---

## FortiDeceptor

**Deception > Integration > Integrate With New Device** (menu path varies by version).

| Field | Value |
|---|---|
| Integrate Method | `FortiGate-WEBHOOK` |
| Expiry | `3600` (or your preferred window) |
| Block URL | `https://<server>/api/v1/ingest/block?deep=true&source=FortiDeceptor&type=Deception&severity=Malicious&confidence=90&tlp=TLP:AMBER&feed_name=FortiDeceptor` |
| Block Authorization | `Bearer <TF_INGEST_TOKENS>` |
| Unblock URL | `https://<server>/api/v1/ingest/unblock?deep=true` |
| Unblock Authorization | `Bearer <TF_INGEST_TOKENS>` |

The `Authorization` field takes the full header value, so the word `Bearer` and the
space before the token are both required.

FortiDeceptor's Expiry setting governs when *it* calls the Unblock URL. Your
`TF_TTL_DAYS` is an independent safety net: even if the unblock call is missed, the
indicator ages out on its own.

### Confirm the payload first

The exact JSON FortiDeceptor sends varies by version, and this integration is not
documented as a generic webhook. Rather than assume, capture one real request:

1. Temporarily set the Block URL to
   `https://<server>/api/v1/ingest/echo`
2. Trigger one decoy event
3. Read what arrived:

```bash
sudo threatfeedctl audit 5
journalctl -u threatfeed -n 20 --no-pager
```

The echo endpoint stores nothing. It returns the payload verbatim plus the IPs the
scanner found:

```json
{"detected_ips":["198.51.100.77"],
 "content_type":"application/json",
 "payload":{"incident":{"attacker":{"ipv4":"198.51.100.77"}}},
 "hint":"Pakai ?deep=true jika detected_ips sudah benar."}
```

If `detected_ips` holds the attacker address and nothing else, switch the URL back to
`/block` and you are done. If it is empty or contains the wrong address, see
[When the scan picks the wrong IP](#when-the-scan-picks-the-wrong-ip).

### Verify end to end

```bash
sudo threatfeedctl feed              # attacker IP should appear
sudo threatfeedctl search 198.51     # source=FortiDeceptor, feed=FortiDeceptor
```

Then trigger an unblock, or wait for FortiDeceptor's expiry, and confirm the status
becomes `revoked` and the IP leaves the feed.

---

## How `?deep=true` chooses an IP

The scanner walks the entire JSON tree and collects every string that parses as a valid,
routable IP address, CIDR block, or range. Loopback, multicast, and unspecified
addresses are discarded.

When several addresses are present, paths containing `attacker`, `source`, `src`,
`remote`, `client`, `offender`, or `malicious` win. Everything else is a fallback used
only when no preferred match exists. So for:

```json
{"incident":{"attacker":{"ipv4":"198.51.100.77"},"sensor":{"ip":"192.168.110.9"}}}
```

only `198.51.100.77` is stored — the sensor's own address is ignored.

`?deep=true` is opt-in for exactly this reason. Enabled blindly on a payload full of
addresses, it would block your own infrastructure.

### When the scan picks the wrong IP

If the hints do not match your payload, three options, in order of preference:

1. **Narrow with `feed_name`** and check the results in the dashboard before trusting
   the integration in a deny policy.
2. **Put the integration behind a small transformer** — a FortiSOAR playbook or a short
   script that receives the webhook and re-emits it in the documented ingest format.
3. **Extend the hint list** in `app/normalize.py`:

   ```python
   _ATTACKER_HINTS = ("attacker", "source", "src", "remote", "client",
                      "offender", "malicious", "your_field_here")
   ```

   Re-run `bash tests/smoke.sh` afterwards.

---

## Generic webhook pattern

The same three features work for any product that can issue an authenticated HTTP POST:

```
POST https://<server>/api/v1/ingest/block?deep=true&source=<name>&feed_name=<name>
Authorization: Bearer <TF_INGEST_TOKENS>
Content-Type: application/json

{ ...whatever the product sends... }
```

Give each integration its own `feed_name`. That keeps them separable in the dashboard,
lets you serve them to different FortiGate objects with `?feed_name=`, and makes
`command: replace` safe — reconciliation is scoped to one feed and will not touch
indicators from other sources.

### Available paths

| Path | Command |
|---|---|
| `/api/v1/ingest` | From the body's `command` field, default `add` |
| `/api/v1/ingest/add`, `/api/v1/ingest/block` | Forced `add` |
| `/api/v1/ingest/delete`, `/api/v1/ingest/unblock` | Forced `delete` |
| `/api/v1/ingest/echo` | Diagnostic. Returns the payload, stores nothing |

All accept `POST` only. The path overrides any `command` present in the body.

### Query parameters

| Parameter | Effect |
|---|---|
| `deep=true` | Scan the whole JSON tree for IPs |
| `source=` | Override the source label |
| `type=` | Override the indicator type |
| `severity=` | Override severity |
| `tlp=` | Override TLP |
| `confidence=` | Override confidence, 0–100 |
| `feed_name=` | Group these indicators under a feed name |
| `comment=` | Comment for entries that carry none |

Query values override anything in the payload, so a product that sends no metadata
still produces well-labelled indicators.

---

## Security notes

- Give each integration **its own ingest token**. `TF_INGEST_TOKENS` is
  comma-separated, and the audit log records a SHA-256 fingerprint per token, so you can
  tell which integration wrote what.
- Add the source IP to `TF_INGEST_ALLOWED_CIDRS`. Confirm the real post-NAT address with
  `sudo threatfeedctl audit`.
- Review the first few days in the dashboard before wiring the feed into a deny policy.
  An integration whose payload you did not design is exactly where a wrong IP will
  appear, and a blocklist is an unforgiving place to discover it.
