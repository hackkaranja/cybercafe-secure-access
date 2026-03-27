import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
RAILWAY_VOLUME_MOUNT_PATH = os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", "").strip()
DEFAULT_DATABASE = (
    os.path.join(RAILWAY_VOLUME_MOUNT_PATH, "cafe_secure.db")
    if RAILWAY_VOLUME_MOUNT_PATH
    else os.path.join(BASE_DIR, "cafe_secure.db")
)
DATABASE = os.environ.get("DATABASE_PATH", DEFAULT_DATABASE)


def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


VERCEL = env_flag("VERCEL", default=False)
if "DATABASE_PATH" not in os.environ and VERCEL and not RAILWAY_VOLUME_MOUNT_PATH:
    DATABASE = "/tmp/cafe_secure.db"


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = env_flag("SESSION_COOKIE_SECURE", default=False)
ADMIN_EMAIL_DOMAIN = os.environ.get("ADMIN_EMAIL_DOMAIN", "").strip().lower().lstrip("@")


def is_strong_password(password):
    return (
        len(password) >= 8
        and bool(re.search(r"[A-Z]", password))
        and bool(re.search(r"[a-z]", password))
        and bool(re.search(r"[^A-Za-z0-9]", password))
    )


def should_assign_admin(email, user_count):
    if user_count == 0:
        return True
    if ADMIN_EMAIL_DOMAIN and email.endswith(f"@{ADMIN_EMAIL_DOMAIN}"):
        return True
    return False


def get_db():
    if "db" not in g:
        database_dir = os.path.dirname(DATABASE)
        if database_dir:
            os.makedirs(database_dir, exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS customer_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            customer_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            terminal_label TEXT NOT NULL,
            access_notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(actor_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            success INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            attempted_at TEXT NOT NULL
        );
        """
    )
    db.commit()


def utcnow():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def log_activity(event_type, details, actor_id=None):
    db = get_db()
    db.execute(
        """
        INSERT INTO activity_logs (actor_id, event_type, details, ip_address, user_agent, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            actor_id,
            event_type,
            details,
            request.headers.get("X-Forwarded-For", request.remote_addr or "unknown"),
            request.headers.get("User-Agent", "unknown"),
            utcnow(),
        ),
    )
    db.commit()


def log_login_attempt(username, success):
    db = get_db()
    db.execute(
        """
        INSERT INTO login_attempts (username, success, ip_address, user_agent, attempted_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            username,
            int(success),
            request.headers.get("X-Forwarded-For", request.remote_addr or "unknown"),
            request.headers.get("User-Agent", "unknown"),
            utcnow(),
        ),
    )
    db.commit()


def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["_csrf_token"] = token
    return token


def validate_csrf():
    submitted = request.form.get("csrf_token", "")
    stored = session.get("_csrf_token", "")
    if not submitted or not stored or not secrets.compare_digest(submitted, stored):
        abort(400, "Invalid CSRF token.")


app.jinja_env.globals["csrf_token"] = generate_csrf_token


@app.context_processor
def inject_user():
    return {
        "current_user": current_user(),
        "admin_email_domain": ADMIN_EMAIL_DOMAIN,
    }


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if current_user() is None:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "admin":
            abort(403)
        return view(**kwargs)

    return wrapped_view


def mask_email(email):
    if "@" not in email:
        return email
    name, domain = email.split("@", 1)
    if len(name) <= 2:
        masked_name = name[0] + "*"
    else:
        masked_name = name[0] + ("*" * (len(name) - 2)) + name[-1]
    return f"{masked_name}@{domain}"


def too_many_failures(username):
    db = get_db()
    window_start = (datetime.utcnow() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    result = db.execute(
        """
        SELECT COUNT(*) AS failures
        FROM login_attempts
        WHERE username = ? AND success = 0 AND attempted_at >= ?
        """,
        (username, window_start),
    ).fetchone()
    return result["failures"] >= 5


@app.route("/")
def index():
    user = current_user()
    db = get_db()
    stats = {
        "users": db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"],
        "records": db.execute("SELECT COUNT(*) AS count FROM customer_records").fetchone()["count"],
        "events": db.execute("SELECT COUNT(*) AS count FROM activity_logs").fetchone()["count"],
    }
    return render_template("index.html", user=user, stats=stats)


@app.route("/health")
def health():
    return {"status": "ok"}, 200


@app.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        validate_csrf()
        full_name = request.form["full_name"].strip()
        username = request.form["username"].strip().lower()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        accepted_terms = request.form.get("accept_terms")

        if not full_name or not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")
        if not is_strong_password(password):
            flash(
                "Password must be at least 8 characters long and include uppercase, lowercase, and a symbol.",
                "danger",
            )
            return render_template("register.html")
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        if accepted_terms != "yes":
            flash("You must read and accept the Privacy Policy and Terms and Conditions before registering.", "danger")
            return render_template("register.html")

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email),
        ).fetchone()
        if existing:
            flash("Username or email already exists.", "danger")
            return render_template("register.html")

        user_count = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        role = "admin" if should_assign_admin(email, user_count) else "user"
        db.execute(
            """
            INSERT INTO users (full_name, username, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (full_name, username, email, generate_password_hash(password), role, utcnow()),
        )
        db.commit()
        actor = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        log_activity("register", f"New {role} account registered: {username}", actor["id"])
        flash("Registration successful. Please sign in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        validate_csrf()
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        db = get_db()

        if too_many_failures(username):
            flash("Too many failed attempts. Please wait 15 minutes and try again.", "danger")
            log_login_attempt(username, False)
            log_activity("login_blocked", f"Login blocked for {username} due to repeated failures")
            return render_template("login.html")

        user = db.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,),
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["_csrf_token"] = secrets.token_hex(16)
            log_login_attempt(username, True)
            log_activity("login_success", f"User signed in: {username}", user["id"])
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))

        log_login_attempt(username, False)
        log_activity("login_failed", f"Failed sign-in for {username}")
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout", methods=("POST",))
@login_required
def logout():
    validate_csrf()
    user = current_user()
    log_activity("logout", f"User signed out: {user['username']}", user["id"])
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    db = get_db()
    if user["role"] == "admin":
        records = db.execute(
            """
            SELECT customer_records.*, users.username AS owner_username
            FROM customer_records
            JOIN users ON users.id = customer_records.owner_id
            ORDER BY customer_records.updated_at DESC
            """
        ).fetchall()
    else:
        records = db.execute(
            """
            SELECT customer_records.*, users.username AS owner_username
            FROM customer_records
            JOIN users ON users.id = customer_records.owner_id
            WHERE owner_id = ?
            ORDER BY customer_records.updated_at DESC
            """,
            (user["id"],),
        ).fetchall()
    return render_template("dashboard.html", records=records, mask_email=mask_email)


@app.route("/records/new", methods=("GET", "POST"))
@login_required
def create_record():
    if request.method == "POST":
        validate_csrf()
        user = current_user()
        customer_name = request.form["customer_name"].strip()
        email = request.form["email"].strip().lower()
        phone = request.form["phone"].strip()
        terminal_label = request.form["terminal_label"].strip()
        access_notes = request.form["access_notes"].strip()

        if not all([customer_name, email, phone, terminal_label]):
            flash("Please complete all required fields.", "danger")
            return render_template("record_form.html", mode="create", record=None)

        db = get_db()
        db.execute(
            """
            INSERT INTO customer_records
            (owner_id, customer_name, email, phone, terminal_label, access_notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user["id"], customer_name, email, phone, terminal_label, access_notes, utcnow(), utcnow()),
        )
        db.commit()
        log_activity("record_created", f"Record created for customer {customer_name}", user["id"])
        flash("Customer record created.", "success")
        return redirect(url_for("dashboard"))

    return render_template("record_form.html", mode="create", record=None)


def fetch_record_or_404(record_id):
    db = get_db()
    record = db.execute("SELECT * FROM customer_records WHERE id = ?", (record_id,)).fetchone()
    if record is None:
        abort(404)
    user = current_user()
    if user["role"] != "admin" and record["owner_id"] != user["id"]:
        abort(403)
    return record


@app.route("/records/<int:record_id>/edit", methods=("GET", "POST"))
@login_required
def edit_record(record_id):
    record = fetch_record_or_404(record_id)

    if request.method == "POST":
        validate_csrf()
        customer_name = request.form["customer_name"].strip()
        email = request.form["email"].strip().lower()
        phone = request.form["phone"].strip()
        terminal_label = request.form["terminal_label"].strip()
        access_notes = request.form["access_notes"].strip()

        db = get_db()
        db.execute(
            """
            UPDATE customer_records
            SET customer_name = ?, email = ?, phone = ?, terminal_label = ?, access_notes = ?, updated_at = ?
            WHERE id = ?
            """,
            (customer_name, email, phone, terminal_label, access_notes, utcnow(), record_id),
        )
        db.commit()
        user = current_user()
        log_activity("record_updated", f"Record updated for customer {customer_name}", user["id"])
        flash("Customer record updated.", "success")
        return redirect(url_for("dashboard"))

    return render_template("record_form.html", mode="edit", record=record)


@app.route("/records/<int:record_id>/delete", methods=("POST",))
@login_required
def delete_record(record_id):
    validate_csrf()
    record = fetch_record_or_404(record_id)
    db = get_db()
    db.execute("DELETE FROM customer_records WHERE id = ?", (record_id,))
    db.commit()
    user = current_user()
    log_activity("record_deleted", f"Record deleted for customer {record['customer_name']}", user["id"])
    flash("Customer record deleted.", "info")
    return redirect(url_for("dashboard"))


@app.route("/monitoring")
@admin_required
def monitoring():
    db = get_db()
    recent_activity = db.execute(
        """
        SELECT activity_logs.*, users.username
        FROM activity_logs
        LEFT JOIN users ON users.id = activity_logs.actor_id
        ORDER BY activity_logs.created_at DESC
        LIMIT 20
        """
    ).fetchall()
    failed_attempts = db.execute(
        """
        SELECT username, ip_address, COUNT(*) AS failures, MAX(attempted_at) AS last_attempt
        FROM login_attempts
        WHERE success = 0
        GROUP BY username, ip_address
        ORDER BY failures DESC, last_attempt DESC
        LIMIT 10
        """
    ).fetchall()
    summary = {
        "active_users": db.execute("SELECT COUNT(*) AS count FROM users WHERE is_active = 1").fetchone()["count"],
        "failed_logins": db.execute("SELECT COUNT(*) AS count FROM login_attempts WHERE success = 0").fetchone()["count"],
        "records": db.execute("SELECT COUNT(*) AS count FROM customer_records").fetchone()["count"],
    }
    return render_template(
        "monitoring.html",
        recent_activity=recent_activity,
        failed_attempts=failed_attempts,
        summary=summary,
    )


@app.route("/reports")
@admin_required
def reports():
    db = get_db()
    user_report = db.execute(
        """
        SELECT users.username, users.role, users.created_at, COUNT(customer_records.id) AS managed_records
        FROM users
        LEFT JOIN customer_records ON customer_records.owner_id = users.id
        GROUP BY users.id
        ORDER BY users.created_at DESC
        """
    ).fetchall()
    return render_template("reports.html", user_report=user_report)


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def handle_error(error):
    return render_template("error.html", error=error), error.code


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=env_flag("FLASK_DEBUG", default=False))
