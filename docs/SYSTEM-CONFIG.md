# System Configuration page

The dashboard has two settings surfaces, and the difference matters:

| | **Pengaturan** | **Konfigurasi Sistem** |
|---|---|---|
| Stores to | `settings` table in SQLite | `/etc/threatfeed/threatfeed.env` |
| Covers | 15 policy values | All 24 variables, including secrets |
| Applies | Immediately, no restart | Rewrites the file, then restarts the service |
| Enabled | Always | **On by default** since this version; opt-out via `TF_ALLOW_ENV_WRITE=false` |
| Needs | A dashboard session | Session **plus** password re-entry, plus a root helper |

Use **Pengaturan** for day-to-day tuning. Use **Konfigurasi Sistem** when you need to
rotate tokens, change the dashboard password, or edit anything that only exists in the
`.env` file.

---

## The security trade-off, stated plainly

This feature lets a web interface rewrite its own credentials. Before enabling it,
understand what changes: without it, a hijacked dashboard session can alter feed policy
and delete indicators. With it, that same session can mint new ingest tokens and change
the admin password — the blast radius goes from "wrong policy" to "attacker owns the
service".

That is why two independent gates stand in front of it regardless of the default:

1. **Password re-entry** on every save. A stolen session cookie alone is not enough.
2. **The root helper re-validates from scratch.** The application is treated as an
   untrusted caller; a bug or an injection in the web tier does not become a config
   write.

It ships **on** because most installs want a working admin page without an extra flag —
but if your threat model does not justify it, turn it off and use `threatfeedctl config`
over SSH instead:

```bash
sudo bash deploy/setup.sh --upgrade --disable-env-editor
```

Nothing else in the product depends on it being enabled.

---

## Architecture

The service account never gets write access to `/etc/threatfeed`, and never gets general
`systemctl` rights.

```
Dashboard ──POST /api/v1/admin/settings──▶ FastAPI (user: threatfeed)
                                             │  validate, then stage
                                             ▼
                              /var/lib/threatfeed/pending.env   (threatfeed, 600)
                                             │  PathExists=
                                  threatfeed-apply-env.path  (systemd)
                                             ▼
                                  threatfeed-apply-env.service (root, oneshot)
                                      ├─ re-validate every line
                                      ├─ back up current .env
                                      ├─ install atomically, root:threatfeed 0640
                                      ├─ write /var/lib/threatfeed/apply-result
                                      └─ systemd-run --on-active=3 systemctl restart
                                             │
                              app polls apply-result for up to 25 s
```

**Why a systemd path unit and not sudo.** The main unit runs with
`NoNewPrivileges=true`, which blocks `sudo` outright — sudo is setuid, and the flag
exists precisely to stop a service from gaining privileges that way. Relaxing it for one
admin feature would weaken the sandbox for everything else the service does. A path unit
sidesteps the conflict entirely: the application only writes a file, and systemd runs the
helper as root. No setuid, no sudoers, and the hardening stays intact.

The application never learns the helper's exit status directly, so the helper writes
`/var/lib/threatfeed/apply-result` (mode 644) and the application polls it. A rejected
candidate is always deleted, otherwise the path unit would re-fire on it in a loop.

**Why a spool file and a helper**, rather than giving the app write access: a
network-facing process that can rewrite its own credential file has no meaningful
boundary left. The helper is a chokepoint that validates independently.

**Why `systemd-run` rather than `systemctl restart` directly**: restarting from inside
the process kills it mid-response, and the dashboard sees a dropped connection instead of
a confirmation. A two-second transient timer lets the HTTP response finish first.

**Why mode 0640 and not 0600**: the service reads this file as group `threatfeed`. At
0600 only root can read it, and the service fails to start. Ownership is
`root:threatfeed` — root writes, the service reads.

---

## Enabling it

```bash
cd /opt/threatfeed-src
sudo bash deploy/setup.sh --upgrade
```

A plain `--upgrade` is enough — this is on by default. It installs the helper to
`/usr/local/sbin/threatfeed-apply-env` (mode 750, `root:root`), installs and enables the
two systemd units, removes any sudoers rule left over from an earlier version, sets
`TF_ALLOW_ENV_WRITE=true`, and restarts the service. (`--enable-env-editor` still works
as an explicit alias, kept for scripts written against the previous default.)

Manual equivalent:

```bash
sudo install -m 750 -o root -g root deploy/threatfeed-apply-env /usr/local/sbin/
sudo install -m 644 -o root -g root deploy/threatfeed-apply-env.service /etc/systemd/system/
sudo install -m 644 -o root -g root deploy/threatfeed-apply-env.path    /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now threatfeed-apply-env.path
sudo sed -i 's|^TF_ALLOW_ENV_WRITE=.*|TF_ALLOW_ENV_WRITE=true|' /etc/threatfeed/threatfeed.env
sudo systemctl restart threatfeed
```

Verify:

```bash
systemctl status threatfeed-apply-env.path      # must be active (waiting)
ls -l /usr/local/sbin/threatfeed-apply-env      # -rwxr-x--- root root
sudo grep TF_ALLOW_ENV_WRITE /etc/threatfeed/threatfeed.env
```

`active (waiting)` is the correct state — the unit sits idle until a candidate file
appears.

### A note on sudo

`deploy/sudoers-threatfeed` ships for reference but is **not used**. An earlier version
called the helper through `sudo -n`, which fails with:

```
sudo: The "no new privileges" flag is set, which prevents sudo from running as root
```

`NoNewPrivileges=true` in the main unit blocks every setuid path, sudo included. If you
prefer the sudo route anyway, you must set `NoNewPrivileges=no` — but that weakens the
sandbox for the whole service to serve one admin feature, which is why the path unit is
the default.

### Disabling it

```bash
sudo bash deploy/setup.sh --upgrade --disable-env-editor
```

Or by hand:

```bash
sudo systemctl disable --now threatfeed-apply-env.path threatfeed-restore-db.path
sudo rm -f /etc/systemd/system/threatfeed-apply-env.{path,service} \
           /etc/systemd/system/threatfeed-restore-db.{path,service} \
           /usr/local/sbin/threatfeed-apply-env /usr/local/sbin/threatfeed-restore-db \
           /etc/sudoers.d/threatfeed
sudo systemctl daemon-reload
sudo sed -i 's|^TF_ALLOW_ENV_WRITE=.*|TF_ALLOW_ENV_WRITE=false|' /etc/threatfeed/threatfeed.env
sudo systemctl restart threatfeed
```

---

## Using the page

Click **Konfigurasi Sistem** in the header. Twenty-four variables in five cards:
Identitas & Storage, Kredensial & Keamanan, Kebijakan Feed, Kontrol Akses Jaringan, and
Retensi & Default Entri. Each field carries a one-line explanation of what it does and
what breaks if it is wrong.

**Secret fields** — ingest tokens, feed tokens, admin password, session key — render
empty with a placeholder showing the current length. The server never sends their values
to the browser; leaving a secret field blank means "leave it alone". Each has a
show/hide toggle and, where applicable, a **Buat acak** button that generates a value
server-side (`secrets.token_hex(32)` for keys, a 20-character alphabet for passwords).

**Saving** requires typing the dashboard password again. The confirmation dialog lists
which keys changed and warns explicitly if you are changing something that will end your
own session.

Every save is written to the audit trail as `env_write`, recording **key names only** —
never values. The audit log must not become a second place where tokens are readable.

---

## Error handling

| What you see | Cause | Fix |
|---|---|---|
| `Pengeditan berkas .env lewat dashboard dinonaktifkan` | `TF_ALLOW_ENV_WRITE=false` (fitur dimatikan manual, atau instalasi lawas sebelum ini jadi default) | `sudo bash deploy/setup.sh --upgrade` |
| `Helper /usr/local/sbin/threatfeed-apply-env tidak terpasang` | Feature enabled but helper missing | Same command; check `ls -l /usr/local/sbin/threatfeed-apply-env` |
| `Password dashboard salah` (401) | Confirmation field wrong | Retype. Failed attempts are logged as `env_write_denied` |
| Red text under a field | Per-field validation failure | The message states the expected format. Nothing was saved — validation is all-or-nothing |
| `Helper menolak perubahan: baris N …` | The helper's independent re-validation rejected a line | Read the reported line number. If it names a key you did not touch, the file was hand-edited into an invalid state |
| `Helper menolak perubahan: kunci wajib hilang` | `TF_INGEST_TOKENS`, `TF_SECRET_KEY`, `TF_ADMIN_PASSWORD`, or `TF_DB_PATH` absent | The helper refuses to install a file that would break startup |
| `sudo: The "no new privileges" flag is set` | Old sudo-based version still installed | Upgrade; the path unit replaces sudo |
| `Berkas kandidat masih tertahan … setelah 25 detik` | `threatfeed-apply-env.path` not enabled | `sudo systemctl enable --now threatfeed-apply-env.path` |
| `Tidak ada berkas hasil dari helper` | Helper failed before writing a result | `journalctl -u threatfeed-apply-env.service -n 30` |
| `kunci ganda: TF_…` | The same key appears twice in `.env`, usually from a manual `echo >>` | Save again — the writer disables the earlier copy and keeps the one that was actually in effect. To fix by hand: `sudo grep -n TF_… /etc/threatfeed/threatfeed.env` and delete all but the last |
| `tidak dapat membaca …env` | Wrong ownership or mode | `sudo chown root:threatfeed /etc/threatfeed/threatfeed.env && sudo chmod 640` |
| `Helper tidak merespons dalam 30 detik` | Helper hung | `journalctl -u threatfeed -n 50`; the `.env` was not modified |
| Dashboard unreachable after a save | The new config broke startup | See recovery below |

### Recovery

Every save backs up the previous file first:

```bash
ls -lt /var/backups/threatfeed/threatfeed.env.*
sudo cp /var/backups/threatfeed/threatfeed.env.<timestamp> /etc/threatfeed/threatfeed.env
sudo chown root:threatfeed /etc/threatfeed/threatfeed.env
sudo chmod 640 /etc/threatfeed/threatfeed.env
sudo systemctl restart threatfeed
sudo threatfeedctl doctor
```

The last 20 backups are kept. If the service will not start at all,
`journalctl -u threatfeed -n 50 --no-pager` names the offending variable.

Locking yourself out of the CIDR allow-lists is not possible from this page:
`127.0.0.1/32` and `::1/128` are re-inserted automatically, so `threatfeedctl` — which
reaches the API over loopback — always keeps working.

---

## Validation rules

Applied in the application, then again independently in the root helper.

| Field type | Rule |
|---|---|
| Integers | Range-checked per field: TTL 0–3650, confidence 0–100, session 1–720 hours, prune interval 60–86400 s |
| Booleans | `true` / `false` only |
| Enums | Must match the listed options exactly |
| CIDR lists | Each entry parsed with Python's `ipaddress`; loopback re-inserted |
| Tokens | `[A-Za-z0-9_-.:]`, 8–256 characters, at most four comma-separated |
| Password | 12–128 characters |
| Session key | Hex, 32–128 characters |
| Paths | Absolute, `[A-Za-z0-9_-./]`, no `..` |
| Free text | Rejects `"` `'` `$`, backtick, backslash, and control characters |

That last rule is the important one. This file is read by systemd's `EnvironmentFile` and
is sometimes sourced by shell scripts, so an unconstrained value is a command execution
primitive. Both layers reject the metacharacters that would make it one — verified in
`tests/env-editor.sh` against `$(id)`, backticks, quote-breakouts, and backslash escapes.

---

## Testing

```bash
bash tests/env-editor.sh
```

Runs against a temporary `.env` and a sandboxed copy of the real helper. Twelve
scenarios: session enforcement, secrets never reaching the browser, eight rejected
malicious inputs, wrong-password refusal, a successful save, comment and ordering
preservation, file mode, backup creation, restart scheduling via `systemd-run`, secret
writes, blank-means-unchanged, audit redaction, the random generators, and the disabled
state.
