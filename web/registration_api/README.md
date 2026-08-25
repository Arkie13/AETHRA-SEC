# AETHRA-SEC registration API

A small, standalone service that captures early-access sign-ups for the
AETHRA-SEC showcase site (`../site/index.html`). It is independent of the
desktop app in `aethra_sec/` - separate dependencies, separate database,
never imported by or importing from the main package.

## What it does

- `POST /register` - name + email, validated, de-duplicated by email, rate
  limited, with a honeypot + minimum-time-since-load bot check.
- `GET /count` - the real aggregate count, safe to show publicly.
- `GET /admin/registrations` - the actual name/email list, gated behind a
  bearer token. This is the only place the data is ever visible.

No accounts, no passwords, no login - see the plan this was built from
(`C:\Users\mark4\.claude\plans\agile-gathering-prism.md`) for what's
explicitly out of scope and why.

## Run locally

```bash
cd web/registration_api
python -m venv .venv
.venv\Scripts\activate        # .venv/bin/activate on Linux/macOS
pip install -r requirements.txt
copy .env.example .env        # cp on Linux/macOS
notepad .env                  # set AETHRA_REG_ADMIN_TOKEN at minimum
uvicorn app.main:app --reload --port 8001
```

Interactive API docs at `http://127.0.0.1:8001/docs`. The SQLite file is
created automatically at `AETHRA_REG_DB_PATH` on first run.

## Deploy

See the plan's "Deployment" section for the full ordered steps (domain,
droplet, Caddy, systemd, backups). Summary:

1. Point a domain (or two subdomains) at a DigitalOcean droplet.
2. Install Caddy with `deploy/Caddyfile` (edit the two domains first).
3. Clone this repo to the droplet, create a venv, install requirements,
   write a real `.env` next to `app/` with production values.
4. Install `deploy/aethra-registration-api.service` to `/etc/systemd/system/`,
   `systemctl enable --now aethra-registration-api`.
5. Copy `../site/index.html` to the path Caddy serves as the static site.
6. Add `deploy/backup-registrations.sh` to cron.

`AETHRA_REG_DB_PATH` in production should point at
`/var/lib/aethra-registration/registrations.db` - persistent disk, never
touched by a code deploy (which only replaces files under
`/opt/aethra-registration`).

## Generating an admin token

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Reading the registration list

```bash
curl -H "Authorization: Bearer <AETHRA_REG_ADMIN_TOKEN>" \
  https://api.aethra-sec.example/admin/registrations
```
