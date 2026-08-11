# Troubleshooting

Start here:

```bash
sudo threatfeedctl doctor
```

It checks the service, port, nginx, certificate SAN against `server_name`, allow-lists,
and prints the real client IPs the server has observed.

---

## `Server not reachable` in FortiGate

This one message covers several unrelated causes. Narrow it down by watching the server
while FortiGate retries:

```bash
sudo tail -f /var/log/nginx/threatfeed.access.log
```

| What appears | Cause | Fix |
|---|---|---|
| Nothing at all | Traffic never arrives | `execute ping <server>` and `execute telnet <server> 443` from FortiGate; check `sudo ss -ltnp \| grep 443` and `sudo ufw status` |
| `404` | The `?` was swallowed when `set resource` was typed in the CLI | Use a query-string-free path, or enter the URL in the GUI |
| `401` | Wrong feed token | `sudo threatfeedctl creds` |
| `403` | Source IP outside `TF_FEED_ALLOWED_CIDRS` | Check the Client column in `sudo threatfeedctl audit 10` — NAT may change it |
| `200` | The fetch worked | The problem is on the FortiGate side; see the certificate section |

### Certificate mismatch

The most common cause when nothing appears in the nginx log at all. A certificate whose
CN is a hostname will be rejected when FortiGate connects by IP:

```bash
openssl x509 -in /etc/ssl/certs/threatfeed-fullchain.pem -noout -text | grep -A1 "Alternative"
```

The SAN must include the address FortiGate uses. Confirm it's the cause in 30 seconds:

```
config system external-resource
    edit "IoC-WATCH-Blocklist"
        set server-identity-check none
    next
end
```

If the status turns green, reissue the certificate with the correct SAN:

```bash
sudo openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout /etc/ssl/private/threatfeed.key \
  -out /etc/ssl/certs/threatfeed-fullchain.pem \
  -subj "/CN=<server-ip>/O=example" \
  -addext "subjectAltName=IP:<server-ip>,DNS:<hostname>"
sudo chmod 600 /etc/ssl/private/threatfeed.key
sudo nginx -t && sudo systemctl reload nginx
```

A self-signed certificate still needs `server-identity-check none` regardless of its
SAN, because the issuer is untrusted. For `full`, issue from a CA whose root you have
imported into FortiGate.

---

## Feed and ingestion

**`entry-list` is empty but the fetch returned `200`.** Every indicator has passed its
TTL, or the parser rejected inline comments. Check both:

```bash
sudo threatfeedctl feed | grep -c .
grep TF_TTL_DAYS /etc/threatfeed/threatfeed.env
```

If `threatfeedctl feed` shows entries but FortiGate shows none, and you are using
`/annotated`, switch to `/api/v1/feed/fortigate/clean`. Inline comments after an IP are
not documented for `address`-type feeds, and rejection is silent.

**Ingestion returns `401`.** Wrong token, or a proxy stripped the `Authorization`
header. `sudo threatfeedctl audit` will show `login_failed` entries if requests are
arriving at all.

**Ingestion returns `403`.** Source IP outside `TF_INGEST_ALLOWED_CIDRS`. Behind a
proxy, confirm `TF_TRUST_PROXY=true` so `X-Forwarded-For` is honoured.

**Ingestion returns `405`.** The HTTP method is `DELETE` or `PUT`. The endpoint only
accepts `POST`; deletion is expressed through `"command": "delete"` in the body.

**Ingestion returns `503`.** `TF_INGEST_TOKENS` is empty.

**Indicators disappear sooner than expected.** Check the clock. TTL is computed from
wall-clock time, so a drifting server expires entries early.

```bash
timedatectl
```

---

## Service and installation

**nginx: `unknown directive "http2"`.** nginx older than 1.25.1 uses
`listen 443 ssl http2;`. The installer detects the version; if you are editing by hand:

```bash
sudo sed -i -e 's|^\(\s*listen 443 ssl\);|\1 http2;|' \
            -e 's|^\(\s*listen \[::\]:443 ssl\);|\1 http2;|' \
            -e '/^\s*http2 on;\s*$/d' \
            /etc/nginx/sites-available/threatfeed.conf
sudo nginx -t && sudo systemctl reload nginx
```

**Dashboard is unreachable from other machines.** You chose `--tls none`, so uvicorn
listens only on loopback. Add nginx:

```bash
sudo bash deploy/setup.sh --upgrade --tls self-signed --domain <server-ip>
```

Or tunnel temporarily: `ssh -L 8080:127.0.0.1:8080 user@<server>`.

**Dashboard asks for login repeatedly.** `TF_SECRET_KEY` is empty, so a new key is
generated on every restart. Set a fixed value from `openssl rand -hex 32`.

**Login appears to succeed but returns to the form.** `TF_COOKIE_SECURE=true` while
accessing over plain HTTP, so the browser discards the cookie. Deploy TLS, or set
`false` for a lab.

**`database is locked`.** Another process is writing to the same file. Keep
`--workers 1`, and never open the database in write mode with `sqlite3` while the
service runs.

**Service fails to start after editing the unit.** `Type=notify` will time out —
uvicorn does not implement `sd_notify`. The shipped unit uses `Type=exec`.

**`threatfeedctl: command not found`.** The installer stopped before installing it:

```bash
sudo install -m 755 deploy/threatfeedctl /usr/local/bin/threatfeedctl
```

**`Permission denied` reading `/etc/threatfeed`.** Expected — mode 750, `root:threatfeed`.
Use `sudo`, or add your user to the `threatfeed` group if you accept that they can then
read both tokens.

**`apt-get update` fails on an unrelated third-party repository.** The installer treats
update as non-fatal and only requires `apt-get install` to succeed. If installation
still fails, fix the repository or install the packages manually.

---

## Diagnostics reference

```bash
sudo threatfeedctl doctor                       # start here
sudo threatfeedctl status
sudo threatfeedctl audit 20                     # who reached the server, and how
journalctl -u threatfeed -n 50 --no-pager
sudo tail -f /var/log/nginx/threatfeed.access.log
sudo ss -ltnp | grep -E ':(443|8080)'
sudo nginx -t
systemd-analyze security threatfeed
```

On FortiGate:

```
execute ping <server>
execute telnet <server> 443
show system external-resource
diagnose sys external-resource list
diagnose sys external-resource entry-list <name>
```
