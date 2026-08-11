# Installation

## Requirements

| | |
|---|---|
| OS | Ubuntu 22.04 / 24.04, Debian 12 |
| Python | 3.10 or newer |
| Hardware | 1 vCPU, 1 GB RAM, 10 GB disk |
| Network | Port 443 reachable from FortiGate and FortiSOAR |

Set the clock before anything else. TTL expiry is computed from wall-clock time, so a
drifting server will expire indicators early or keep them past their window.

```bash
sudo timedatectl set-timezone Asia/Jakarta
timedatectl        # expect: System clock synchronized: yes
```

## Values to collect first

| Value | How to find it |
|---|---|
| Server IP or FQDN | `hostname -I` |
| FortiSOAR source IP | The address your playbooks egress from |
| FortiGate IP or subnet | The address that will pull the feed |

If NAT sits in the path, use the **post-NAT** address — what the server actually sees.
You can confirm it later with `threatfeedctl audit`.

## Install

Put the project somewhere permanent. `/tmp` is cleared on reboot, and without the
project directory `--upgrade` and `--uninstall` are unavailable.

```bash
sudo mkdir -p /opt/threatfeed-src
sudo unzip threatfeed.zip -d /tmp/tf && sudo cp -r /tmp/tf/threatfeed/. /opt/threatfeed-src/
cd /opt/threatfeed-src
sudo bash deploy/setup.sh
```

The wizard asks for the domain, FortiSOAR IP, FortiGate IP, TTL, whether to include
comments in the feed, and the TLS mode. Everything else is automatic: system packages,
a locked `threatfeed` service account, a virtualenv under `/opt/threatfeed/.venv`, the
database in `/var/lib/threatfeed/`, random credentials in `/etc/threatfeed/threatfeed.env`
(mode 640), the systemd unit, nginx with TLS, ufw rules, a functional self-test, and the
`threatfeedctl` command.

**Record the credentials printed at the end.** They are also saved to
`/etc/threatfeed/INSTALL-SUMMARY.txt`, along with a ready-to-paste FortiGate
configuration block.

## Flags

```bash
sudo bash deploy/setup.sh --yes \
  --domain feed.example.com \
  --soar-ip 10.10.10.20 \
  --fgt-ip 10.10.10.0/24 \
  --ttl 30 \
  --tls existing --cert /etc/ssl/certs/feed.pem --key /etc/ssl/private/feed.key \
  --comments --comment-format plain
```

| Flag | Effect |
|---|---|
| `--domain` | Address FortiGate and FortiSOAR will use. Defaults to the primary IP |
| `--soar-ip`, `--fgt-ip` | CIDR allow-lists. Accepts a bare IP or a subnet |
| `--ttl` | Days before an unrefreshed indicator leaves the feed. `0` disables expiry |
| `--tls self-signed` | nginx plus a generated certificate. FortiGate needs `server-identity-check none` |
| `--tls existing --cert … --key …` | nginx with your own certificate |
| `--tls none` / `--no-nginx` | uvicorn on `127.0.0.1` only, no nginx |
| `--port` | Internal uvicorn port. Default 8080 |
| `--comments` / `--no-comments` | Include comments in the FortiGate feed |
| `--comment-format plain\|short\|full` | Comment contents. Default `plain` |
| `--yes` | Accept all defaults, no prompts |
| `--upgrade` | Refresh code only; credentials, database, and nginx config preserved |
| `--uninstall` | Remove cleanly. Database kept unless you confirm otherwise |

A failed fresh install rolls itself back: the service stops, the unit and
`/opt/threatfeed` are removed, while `/etc/threatfeed` and `/var/lib/threatfeed` are
left untouched.

## TLS

**Production.** Issue a certificate whose SAN covers the **IP address** FortiGate will
use, not just the hostname, then import your Root CA into FortiGate under
**System > Certificates > Import > CA Certificate**. A certificate with only a hostname
CN is the most common cause of FortiGate reporting `Server not reachable`.

**Lab.** `--tls self-signed` generates a certificate with the correct SAN
automatically. FortiGate will still need `set server-identity-check none`, because the
issuer is untrusted regardless of the SAN.

**Replacing a certificate later:**

```bash
sudo cp fullchain.pem /etc/ssl/certs/threatfeed-fullchain.pem
sudo cp privkey.pem   /etc/ssl/private/threatfeed.key
sudo chmod 600 /etc/ssl/private/threatfeed.key
sudo nginx -t && sudo systemctl reload nginx
```

Use `fullchain.pem`, not `cert.pem` alone — FortiGate needs the intermediate chain.

## Verify

```bash
sudo threatfeedctl doctor
```

Expect `0 failed`. The check watches ten common failure points, including whether the
certificate SAN matches the nginx `server_name`.

```bash
sudo ss -ltnp | grep -E ':(443|8080)'
```

Correct output shows `127.0.0.1:8080` (uvicorn) and `0.0.0.0:443` (nginx). uvicorn
staying on loopback is deliberate — nginx faces the network and handles TLS.

Then test from a client, which exercises routing, firewall, and TLS at once:

```bash
curl -v -u fortigate:<FEED_TOKEN> https://<server>/api/v1/feed/fortigate
```

| Result | Meaning |
|---|---|
| `200` plus IP list | Ready |
| `401` | Wrong token |
| `403` | Source IP outside `TF_FEED_ALLOWED_CIDRS` |
| `404` | Wrong path — check for a missing `?` |
| Connection refused | Firewall, routing, or nginx not running |

## Manual installation

If you prefer to see each step, `deploy/install.sh` is a minimal version of the same
flow. Or do it by hand:

```bash
sudo useradd --system --home-dir /var/lib/threatfeed --shell /usr/sbin/nologin threatfeed
sudo install -d -o threatfeed -g threatfeed -m 750 /opt/threatfeed /var/lib/threatfeed
sudo install -d -o root -g threatfeed -m 750 /etc/threatfeed

sudo cp -r app static requirements.txt /opt/threatfeed/
sudo python3 -m venv /opt/threatfeed/.venv
sudo /opt/threatfeed/.venv/bin/pip install -r /opt/threatfeed/requirements.txt
sudo chown -R threatfeed:threatfeed /opt/threatfeed

sudo cp deploy/threatfeed.env.example /etc/threatfeed/threatfeed.env
sudo chmod 640 /etc/threatfeed/threatfeed.env
sudo chown root:threatfeed /etc/threatfeed/threatfeed.env
sudo nano /etc/threatfeed/threatfeed.env      # fill in every GANTI_* value

sudo cp deploy/threatfeed.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now threatfeed
sudo install -m 755 deploy/threatfeedctl /usr/local/bin/threatfeedctl
```

Generate secrets with `openssl rand -hex 32`. Leaving `TF_SECRET_KEY` empty makes the
dashboard session break on every restart, because a fresh key is generated each time.

## Upgrading

```bash
cd /opt/threatfeed-src
sudo unzip -o ~/threatfeed-new.zip -d /tmp/tf && sudo cp -r /tmp/tf/threatfeed/. .
sudo bash deploy/setup.sh --upgrade
sudo threatfeedctl doctor
```

Code only. Credentials, database, and nginx configuration are preserved; the previous
version is backed up to `/var/lib/threatfeed/rollback-*`. To change the domain or
certificate during an upgrade, pass `--domain` or `--tls` explicitly.

## Uninstalling

```bash
sudo bash deploy/setup.sh --uninstall
```

The service, unit, nginx site, and `/opt/threatfeed` are removed. The database in
`/var/lib/threatfeed` and configuration in `/etc/threatfeed` are kept unless you confirm
deletion when prompted.

## Backups

```bash
sudo threatfeedctl backup
```

Uses SQLite's `.backup`, which is safe while the service is running. A plain `cp` is
not: recent transactions may still live in the `-wal` file, and the copy will be missing
them. Schedule it:

```bash
sudo tee /etc/cron.d/threatfeed-backup <<'EOF'
0 2 * * * root /usr/local/bin/threatfeedctl backup >/dev/null 2>&1
EOF
```

The last fourteen backups are retained automatically.
