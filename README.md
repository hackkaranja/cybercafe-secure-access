# CyberCafe Secure Access

CyberCafe Secure Access is a secure web-based system for local internet cafes. It combines account access control, customer record management, user activity monitoring, and administrative reporting in one browser-based application.

## Features mapped to the objectives

- Secure registration, login, and session management with password hashing and CSRF validation.
- CRUD operations for customer records so staff can input, store, retrieve, update, and delete data accurately.
- Monitoring and reporting with audit logs, failed login tracking, and summary dashboards.
- Responsive user interface designed for browser compatibility and future extension.

## Technology

- Python
- Flask
- SQLite
- HTML and CSS

## Run locally

1. Create a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Start the application with `python app.py`.
4. Open `http://127.0.0.1:5000`.

## Deploy

This project is now set up for hosts that can run a Python web process with:

- `pip install -r requirements.txt`
- `gunicorn wsgi:app`

Quick deployment flow:

1. Push the project to GitHub.
2. Create a new web service on your hosting platform.
3. Set the build command to `pip install -r requirements.txt`.
4. Set the start command to `gunicorn wsgi:app`.
5. Add a strong `SECRET_KEY` environment variable.
6. Set `SESSION_COOKIE_SECURE=True` in production.

Important SQLite note:

- The app currently uses the local file `cafe_secure.db`.
- Many cloud platforms use ephemeral filesystems, so SQLite data can be lost on redeploy or restart.
- For a real public deployment, move to a managed database such as PostgreSQL, or use a host that provides persistent disk storage.

## Deploy on Render

This repo now includes [render.yaml](/abs/path/c:/Users/User/Desktop/New%20folder/render.yaml) for a Render web service.

It is configured to:

- install dependencies with `pip install -r requirements.txt`
- start the app with `gunicorn wsgi:app`
- generate `SECRET_KEY` automatically
- store the SQLite database at `/opt/render/project/src/data/cafe_secure.db`
- mount a persistent disk at `/opt/render/project/src/data`

Render setup:

1. Push this project to GitHub.
2. In Render, create a new Blueprint or Web Service from the repository.
3. If you use the included `render.yaml`, review the service name and settings before creating it.
4. Wait for the first deploy to finish, then open the Render URL.

Notes for Render:

- Render's filesystem is ephemeral by default, so the persistent disk is important for SQLite.
- Persistent disks on Render require a paid web service plan.
- If you want a free Render deployment, we should switch this project from SQLite to PostgreSQL.

## Notes

- The first registered account becomes the administrator.
- Any account using the configured `ADMIN_EMAIL_DOMAIN` email domain is also registered as an administrator.
- Set `SECRET_KEY` in your environment for production use.
- Set `SESSION_COOKIE_SECURE=True` when deploying over HTTPS.

## IDS demo

An educational network-monitoring demo is included in `ids_demo.py`. It uses two basic Snort/Suricata-style rules from `ids_demo.rules`:

- Port scan detection
- SSH brute-force pattern detection

Run it locally with:

```bash
python ids_demo.py --demo
```

The script starts localhost listeners, simulates a scan and repeated SSH authentication failures, and writes alerts to:

- `ids_fast.log`
- `ids_eve.jsonl`

This is a proof-of-concept for demonstrating "the cafe is now monitoring the network." For production, use a real IDS such as Snort or Suricata, and consider cyber-cafe management suites like CyberCafePro, CafeSuite, or Antamedia for session timers, lock screens, filtering, and usage logs.
