# Installing AETHRA-SEC on Windows

This guide covers a clean Windows 10/11 workstation. Every step is verifiable:
after each one there is a command whose output tells you whether it worked.
Nothing here needs Internet access at runtime — AETHRA-SEC is a local
application (§88).

> **Authorisation first.** Before installing, be certain you are permitted to
> scan and monitor the network you will point this at. AETHRA-SEC refuses
> targets outside `AETHRA_AUTHORIZED_NETWORKS`, but the responsibility for
> setting that boundary correctly is yours.

---

## 1. Python 3.10-3.14 with Tkinter

Install from <https://www.python.org/downloads/windows/>. Any version from 3.10
to 3.14 works; 3.12 or 3.13 is the smoothest, because some third-party wheels
(PyShark's dependencies in particular) publish 3.14 builds later than the rest.

* Tick **"Add python.exe to PATH"**.
* Under *Optional Features*, keep **"tcl/tk and IDLE"** ticked — without it the
  desktop interface cannot start.

```bat
python --version
python -c "import tkinter; print('tkinter ok')"
```

If the second command fails, re-run the Python installer, choose *Modify*, and
enable *tcl/tk and IDLE*.

---

## 2. MySQL (or MariaDB)

Install MySQL Community Server 8.0+ (<https://dev.mysql.com/downloads/mysql/>)
and keep the service set to start automatically.

Create the schema owner with the least privilege it needs. In MySQL Workbench
or `mysql -u root -p`:

```sql
CREATE DATABASE aethra_sec CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'aethra_app'@'localhost' IDENTIFIED BY 'choose-a-strong-password';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES, DROP
  ON aethra_sec.* TO 'aethra_app'@'localhost';
FLUSH PRIVILEGES;
```

`CREATE`, `ALTER`, `INDEX`, `REFERENCES` and `DROP` are needed only while
migrations run. After the first successful start you may revoke them and leave
the account with `SELECT, INSERT, UPDATE, DELETE`; run `python -m
aethra_sec.main --no-migrate` from then on, and re-grant when upgrading.

```bat
mysql -u aethra_app -p -e "SELECT VERSION();"
```

---

## 3. Nmap

Install from <https://nmap.org/download.html> (the installer includes Npcap —
accept it, it is the same driver TShark needs).

Default path: `C:\Program Files (x86)\Nmap\nmap.exe`

```bat
nmap --version
```

If `nmap` is not on `PATH`, set `AETHRA_NMAP_PATH` in `.env` to the full path.

---

## 4. Wireshark / TShark

Install from <https://www.wireshark.org/download.html>.

* Install **Npcap** when offered (or keep the one Nmap installed).
* Tick **"Support raw 802.11 traffic"** only if you need wireless monitor mode.
* Tick **"Install Npcap in WinPcap API-compatible mode"**.

Default path: `C:\Program Files\Wireshark\tshark.exe`

```bat
"C:\Program Files\Wireshark\tshark.exe" -v
"C:\Program Files\Wireshark\tshark.exe" -D
```

The second command lists the interfaces AETHRA-SEC will offer. If it prints
nothing, Npcap is not installed correctly or you need an elevated prompt.

Set `AETHRA_TSHARK_PATH` in `.env` if TShark is not on `PATH`.

**Capture privileges.** Live capture needs the Npcap driver and, in most
installations, an elevated process. Either install Npcap with *"Restrict Npcap
driver's access to Administrators only"* unticked, or start AETHRA-SEC from an
Administrator prompt. The System Health screen states plainly whether the
process has capture privileges — it never claims capture is running when it is
not.

---

## 5. Snort (optional)

AETHRA-SEC **consumes** Snort alerts; it never generates them. Skip this
section to run with `AETHRA_SNORT_TRANSPORT=disabled` — the interface will
report *"Snort unavailable"* and every other subsystem still works.

Windows has no Unix domain sockets, so the classic Alert Socket IPC transport
(`alert_unixsock`) is available only on Linux or WSL. On Windows use the
**file** transport (simplest) or the **syslog** transport.

1. Install Snort from <https://www.snort.org/downloads> and its rule set.
2. In `snort.conf`, enable a text alert output, for example:
   `output alert_fast: alert.ids`
3. Run the sensor against your monitored interface.
4. In `.env`:

```ini
AETHRA_SNORT_TRANSPORT=file
AETHRA_SNORT_ALERT_FILE=C:\Snort\log\alert.ids
AETHRA_SNORT_PATH=C:\Snort\bin\snort.exe
AETHRA_SNORT_CONFIG=C:\Snort\etc\snort.conf
```

Complete configuration for all four transports, the alert formats and how to
verify ingest is in [`SNORT_INTEGRATION.md`](SNORT_INTEGRATION.md).

---

## 6. AETHRA-SEC itself

### The quick path: setup.bat

With the prerequisites above installed, `setup.bat` does steps 6, 7 and 8 for
you: it checks Python and tkinter, creates the virtual environment, installs the
dependencies, copies `.env.example` to `.env` and opens it in Notepad, creates
the database schema, offers to create the first administrator, and finishes by
running the diagnostics.

```bat
cd C:\path\to\AETHRA-SECNEW
setup.bat
```

It is safe to run again — every step checks what is already done. If a step
fails it says why and stops, so nothing half-configured is left behind.

After that, start the console with **`run.bat`** (see step 8).

### Or by hand

```bat
cd C:\path\to\AETHRA-SECNEW
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Then create your configuration:

```bat
copy .env.example .env
notepad .env
```

Set at minimum:

```ini
AETHRA_DB_HOST=127.0.0.1
AETHRA_DB_NAME=aethra_sec
AETHRA_DB_USER=aethra_app
AETHRA_DB_PASSWORD=the-password-you-chose

AETHRA_AUTHORIZED_NETWORKS=192.168.1.0/24
AETHRA_TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
AETHRA_NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
```

`.env` holds credentials. It is listed in `.gitignore` and must never be
committed or shared.

---

## 7. Create the schema and the first account

```bat
python scripts\init_db.py
```

Or, to build the schema straight from SQL without running the application
(useful when a DBA owns the database server):

```bat
mysql -u root -p < sql\aethra_sec_schema.sql
```

Both produce the same schema. Expected output ends with the schema version,
`Schema check : OK`, and a record count of **0** for every evidence table. That zero is correct: seeding creates
roles, permissions, thresholds and the mitigation knowledge base, and nothing
else.

```bat
python scripts\create_admin.py --username admin
```

The password is prompted for and never echoed; only its Argon2id hash is
stored. It must be at least 12 characters with three character classes.

---

## 8. Verify, then start

```bat
python scripts\health_check.py
```

Read the report rather than the exit code alone. Warnings are normal on a fresh
installation — no interface selected yet, Snort disabled, capture stopped. A
**FAIL** row names what is wrong and what to do about it.

```bat
run.bat
```

or, with the environment activated, `python -m aethra_sec.main`. `run.bat`
passes any argument through, so:

```bat
run.bat --check        :: diagnostics, then exit
run.bat --headless     :: services without the interface
run.bat --no-migrate   :: start without touching the schema
```

**Live capture needs privileges.** If the interface list on the Network
Monitoring screen is empty, close AETHRA-SEC, right-click `run.bat` and choose
*Run as administrator*.

Sign in with the account you just created. The dashboard will be empty until
you start a capture or run an assessment.

### First useful actions

1. **Network Monitoring** → choose your interface → **Start Capture**. Packets
   appear within a second or two on a live network.
2. **Vulnerability Assessment** → enter a target inside your authorised
   networks → choose a profile → **Start Scan**.
3. **Dashboard** → the tiles now show what those two subsystems actually
   observed.

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `DATABASE OFFLINE` on the login window | MySQL service stopped, or wrong credentials in `.env`. Test with `mysql -u aethra_app -p`. |
| `The database 'aethra_sec' does not exist and could not be created` | The account lacks `CREATE`. Create the schema manually (step 2) and re-run `init_db.py`. |
| The desktop interface will not start; "Tkinter is not available" | Python installed without tcl/tk. Re-run the installer → *Modify* → enable *tcl/tk and IDLE*. |
| Interface list is empty on the Monitoring screen | Npcap missing, or the process is not elevated. Check `tshark -D` in the same kind of prompt. |
| Capture starts then stops immediately | Another capture holds the interface, or the BPF filter is invalid. The status line shows TShark's own error text. |
| `NMAP NOT FOUND` on the Assessment screen | Set `AETHRA_NMAP_PATH` to the full path of `nmap.exe`. |
| "Target refused: outside the authorised networks" | Intended. Add the network to `AETHRA_AUTHORIZED_NETWORKS` only if you are authorised to assess it. |
| Snort shows "unavailable" although Snort is running | The transport is not configured, or the alert file path is wrong. See [`SNORT_INTEGRATION.md`](SNORT_INTEGRATION.md). |
| Scan runs but every host is "down" | Windows unprivileged scans use TCP connect. Elevate the prompt for ICMP/SYN discovery profiles. |
| `LOG INTEGRITY WARNING` on the Logs screen | The audit chain does not verify. Investigate — this is reported, never silently repaired. See [`SECURITY.md`](SECURITY.md). |

Application logs are written to the directory named by `AETHRA_LOG_DIR`
(default `logs/`), rotated, and viewable on the **Logs & Audit** screen.

---

## Upgrading

1. Stop AETHRA-SEC.
2. Back up the database (see [`DATABASE.md`](DATABASE.md)).
3. Pull the new version and `pip install -r requirements.txt`.
4. Run `python scripts\init_db.py` — migrations are versioned, recorded in
   `schema_migrations` and applied once.
5. Run `python scripts\health_check.py` before signing in.
