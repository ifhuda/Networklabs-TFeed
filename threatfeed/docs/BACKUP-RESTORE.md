# Backup and restore

Three separate mechanisms, easy to confuse:

| | Automatic backup | Export | `threatfeedctl backup` |
|---|---|---|---|
| Runs as | The service itself | On demand, from the browser | root, from cron or by hand |
| Writes to | `TF_BACKUP_DIR` | Your download folder | `/var/backups/threatfeed/` |
| Format | SQLite `.db` | CSV / JSON / `.db` | SQLite `.db` |
| Can be restored from the GUI | Yes | Yes, by uploading | No — copy it into `TF_BACKUP_DIR` first |

---

## Automatic backup

On by default: a snapshot every 24 hours, keeping the last 14. Configure it under
**Konfigurasi Sistem → Backup & Pemulihan**, or in `.env`:

| Key | Default | Meaning |
|---|---|---|
| `TF_BACKUP_ENABLED` | `true` | Master switch |
| `TF_BACKUP_INTERVAL_HOURS` | `24` | Hours between snapshots |
| `TF_BACKUP_KEEP` | `14` | How many to retain; older ones are deleted |
| `TF_BACKUP_DIR` | `<db dir>/backups` | Must be writable by the service account |

The schedule is computed from the **timestamp of the newest existing backup**, not from
an in-memory timer. A service that restarts every few hours would otherwise either never
reach its interval or take a snapshot on every start; reading the timestamp from disk
makes the interval hold regardless.

Snapshots use SQLite's `backup` API, so they are safe to take while the service is
running. A plain `cp` is not: recent transactions may still be in the `-wal` file and the
copy would silently miss them.

Files named `*-pre-restore.db` are **never rotated away**. They are your undo for a
restore decision, and rotation deleting them is exactly the moment you would need one.

---

## The Backup page

**Backup** in the header opens the panel. It lists every snapshot with size, age, and
type, plus buttons to download, delete, or restore each one. **Buat backup sekarang**
takes an immediate snapshot and applies rotation.

At the bottom, **Pulihkan dari berkas** accepts a `.db` upload — for moving data between
servers, or recovering from a backup you archived elsewhere.

---

## Restoring

Restore replaces the **entire** database: indicators, audit trail, and settings
overrides. Three safeguards stand in front of it.

**1. The candidate is validated before anything is touched.** The file must be a real
SQLite database, pass `quick_check`, contain the `indicators` and `audit_log` tables, and
have the expected columns. Upload an unrelated file and you get a rejection, not a dead
service:

```
bukan berkas database SQLite
tabel wajib tidak ada: audit_log
```

Use **Periksa berkas** first — it reports indicator count, audit entries, and the newest
timestamp without changing anything.

**2. A pre-restore snapshot is taken automatically.** Before the swap, the current
database is saved as `threatfeed-<stamp>-pre-restore.db`. Restoring the wrong file is
recoverable: restore the pre-restore copy.

**3. The dashboard password must be re-entered.** A stolen session cookie is not enough
to wipe the database.

### What happens mechanically

The application does not swap the file itself — replacing a database under live SQLite
connections leaves the process reading a deleted inode. It writes a candidate to a spool
file, and a systemd path unit runs the helper as root:

```
Dashboard ──POST /api/v1/backups/restore──▶ app (user: threatfeed)
                                              │ validate, pre-restore snapshot, stage
                                              ▼
                            /var/lib/threatfeed/restore-pending.db
                                              │ PathExists=
                                 threatfeed-restore-db.path (systemd)
                                              ▼
                             threatfeed-restore-db.service (root)
                                   ├─ systemctl stop threatfeed
                                   ├─ move current db aside as .replaced-<stamp>
                                   ├─ delete stale -wal / -shm
                                   ├─ install the candidate, threatfeed:threatfeed 0640
                                   ├─ record restore_applied in the NEW database
                                   └─ systemctl start threatfeed
```

Recording `restore_applied` **after** the swap matters: the restore overwrites the audit
log along with everything else, so without this the single most consequential event in
the system's history would leave no trace anywhere. It is written before the service
starts, so the `-wal` file it creates does not end up owned by root.

**If the service fails to start with the new database**, the helper puts the old one back
and starts the service again. A failed restore must not take the feed down with it — a
FortiGate that stops receiving its blocklist is worse than a failed restore.

The five most recent replaced databases are kept as `threatfeed.db.replaced-<stamp>` in
the data directory.

### Enabling restore

The helper ships with the same flag as the `.env` editor:

```bash
sudo bash deploy/setup.sh --upgrade --enable-env-editor
systemctl status threatfeed-restore-db.path      # expect: active (waiting)
```

Without it, backups still work — creation, rotation, download, and upload validation are
all unaffected. Only the restore button is unavailable, and the panel says so.

---

## Recovering without the GUI

If the dashboard is unreachable, everything is a plain file:

```bash
sudo ls -lt /var/lib/threatfeed/backups/
sudo systemctl stop threatfeed
sudo cp /var/lib/threatfeed/threatfeed.db /var/lib/threatfeed/threatfeed.db.manual-$(date +%s)
sudo rm -f /var/lib/threatfeed/threatfeed.db-wal /var/lib/threatfeed/threatfeed.db-shm
sudo cp /var/lib/threatfeed/backups/threatfeed-<stamp>.db /var/lib/threatfeed/threatfeed.db
sudo chown threatfeed:threatfeed /var/lib/threatfeed/threatfeed.db
sudo chmod 640 /var/lib/threatfeed/threatfeed.db
sudo systemctl start threatfeed
sudo threatfeedctl doctor
```

Deleting the `-wal` and `-shm` files is not optional. They belong to the database you are
replacing, and leaving them in place lets SQLite apply a log from a different database on
next open.

Verify a file before trusting it:

```bash
sudo -u threatfeed sqlite3 /var/lib/threatfeed/backups/threatfeed-<stamp>.db \
  "PRAGMA quick_check; SELECT COUNT(*) FROM indicators; SELECT MAX(updated_at) FROM indicators;"
```

---

## Off-server copies

Everything above lives on the same disk as the database. That covers operator error and
bad upgrades, not disk failure or a lost VM. Copy snapshots off the host:

```bash
sudo tee /etc/cron.d/threatfeed-offsite <<'EOF'
30 3 * * * root rsync -a --delete /var/lib/threatfeed/backups/ backup-host:/srv/ioc-watch/
EOF
```

These files contain the full audit trail including client IP addresses. Store them
encrypted and restrict access accordingly.

---

## Errors

| Message | Cause | Fix |
|---|---|---|
| `Helper … tidak terpasang` | Restore helper missing | `sudo bash deploy/setup.sh --upgrade --enable-env-editor` |
| `bukan berkas database SQLite` | Wrong file uploaded | Check what you picked; use **Periksa berkas** |
| `tabel wajib tidak ada` | A SQLite file, but not from IoC-WATCH | Use a snapshot from this application |
| `pemeriksaan integritas SQLite gagal` | Corrupt file, often a truncated transfer | Re-copy it; verify with `sqlite3 … "PRAGMA quick_check"` |
| `Password dashboard salah` | Confirmation wrong | Retype; failures are logged as `restore_denied` |
| `Kandidat masih tertahan di spool` | `threatfeed-restore-db.path` not enabled | `sudo systemctl enable --now threatfeed-restore-db.path` |
| `service gagal start dengan database baru` | The restored file broke startup | The helper already rolled back; check `journalctl -u threatfeed -n 50` |
| Backup directory empty | `TF_BACKUP_ENABLED=false`, or the directory is not writable | `sudo threatfeedctl doctor`; check ownership of `TF_BACKUP_DIR` |

---

## Testing

```bash
bash tests/backup-restore.sh
```

Fourteen scenarios against a temporary database and a sandboxed copy of the real helper:
schedule reporting, manual snapshot, rotation honouring `TF_BACKUP_KEEP`, three
path-traversal attempts, validation of random bytes and of a foreign SQLite file,
wrong-password refusal, a full restore cycle verifying the data actually reverts,
pre-restore snapshot creation, stale `-wal`/`-shm` cleanup, the `restore_applied` record
landing in the restored database, and audit coverage.
