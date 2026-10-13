import os
import re
import sqlite3
import csv
import io
from flask import Flask, request, render_template, redirect, url_for, session, g, flash, Response
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

USERNAME_PATTERN = re.compile(r'^[A-Za-z][A-Za-z0-9_.]{2,19}$')


def validate_username(username):
    if not USERNAME_PATTERN.match(username):
        return ("Username must be 3-20 characters, start with a letter, and contain "
                "only letters, numbers, underscores, or periods.")
    return None


def validate_password(password):
    if not (5 <= len(password) <= 64):
        return "Password must be between 5 and 64 characters."
    if not re.search(r'[a-z]', password):
        return "Password must include at least one lowercase letter."
    if not re.search(r'[A-Z]', password):
        return "Password must include at least one uppercase letter."
    if not re.search(r'\d', password):
        return "Password must include at least one number."
    if not re.search(r'[^A-Za-z0-9\s]', password):
        return "Password must include at least one special character (a space doesn't count)."
    return None


def is_debug_mode():
    # FIX (vuln #8): debug mode must be explicitly opted into via an env
    # var, never hardcoded True. Flask's debug mode exposes an interactive
    # in-browser Python console on unhandled errors -- remote code
    # execution if that page is ever reachable outside your own machine.
    return os.environ.get("FLASK_DEBUG", "0") == "1"


def load_secret_key():
    # FIX (vuln #6, hardened): no hardcoded fallback. The app refuses to
    # start without a real key; local development opts out explicitly
    # with FLASK_DEBUG=1.
    secret = os.environ.get("SECRET_KEY")
    if secret:
        return secret
    if is_debug_mode():
        return "dev-only-insecure-key"
    raise RuntimeError(
        "SECRET_KEY is not set. Set it to a long random value "
        "(python -c \"import secrets; print(secrets.token_hex(32))\"), "
        "or set FLASK_DEBUG=1 for local development only."
    )


app = Flask(__name__)
app.secret_key = load_secret_key()

# FIX: harden session cookie settings. SECURE is on by default (it needs
# HTTPS) and is switched off only in local debug mode, or explicitly with
# COOKIE_SECURE=0 when testing over plain http://127.0.0.1.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0" if is_debug_mode() else "1") == "1",
)

# FIX: CSRF protection enabled globally — forms must now include a valid
# csrf_token or their POST requests will be rejected with a 400 error.
csrf = CSRFProtect(app)

# FIX: rate limiting. /login has a strict per-route limit (below); every
# other route falls back to a generous global default so no endpoint is
# completely unthrottled.
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per hour"])


# FIX: basic security headers on every response.
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "script-src 'self' 'unsafe-inline'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


DB_PATH = "vuln.db"

CURRENCIES = {
    "ZAR": {"symbol": "R", "rate": 1.0, "name": "South African Rand (ZAR)"},
    "USD": {"symbol": "$", "rate": 0.054, "name": "US Dollar (USD)"},
    "EUR": {"symbol": "€", "rate": 0.050, "name": "Euro (EUR)"},
    "GBP": {"symbol": "£", "rate": 0.043, "name": "British Pound (GBP)"},
}

def format_money(amount_zar, currency_code="ZAR"):
    curr = CURRENCIES.get(currency_code, CURRENCIES["ZAR"])
    converted = float(amount_zar or 0) * curr["rate"]
    return f"{curr['symbol']} {converted:,.2f}"

@app.context_processor
def inject_currency_and_user():
    curr_code = session.get("currency", "ZAR")
    return {
        "current_currency": curr_code,
        "currency_info": CURRENCIES.get(curr_code, CURRENCIES["ZAR"]),
        "currencies": CURRENCIES,
        "format_money": lambda amt: format_money(amt, curr_code),
        "is_admin": session.get("is_admin", False),
    }


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            client_name TEXT NOT NULL,
            pickup_location TEXT NOT NULL,
            delivery_location TEXT NOT NULL,
            notes TEXT,
            amount REAL DEFAULT 1850.00,
            payment_status TEXT NOT NULL DEFAULT 'Pending',
            delivery_status TEXT NOT NULL DEFAULT 'Pending Dispatch',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # Ensure schema migrations for existing databases
    cursor = db.cursor()
    cursor.execute("PRAGMA table_info(users)")
    u_cols = [col[1] for col in cursor.fetchall()]
    if u_cols and "is_admin" not in u_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")

    cursor.execute("PRAGMA table_info(bookings)")
    b_cols = [col[1] for col in cursor.fetchall()]
    if b_cols and "created_at" not in b_cols:
        cursor.execute("ALTER TABLE bookings ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    if b_cols and "amount" not in b_cols:
        cursor.execute("ALTER TABLE bookings ADD COLUMN amount REAL DEFAULT 1850.00")

    # Seed admin account if it doesn't exist
    admin_row = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
    if not admin_row:
        admin_pass = generate_password_hash("Str0ng!AdminPass1")
        db.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES ('admin', ?, 1)", (admin_pass,))

    db.commit()
    db.close()


@app.route("/")
def home():
    if "user_id" not in session:
        return render_template("landing.html")
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("bookings"))


@app.route("/set-currency/<curr_code>", methods=["POST", "GET"])
def set_currency(curr_code):
    curr_code = curr_code.upper()
    if curr_code in CURRENCIES:
        session["currency"] = curr_code
        flash(f"Display currency set to {CURRENCIES[curr_code]['name']}.", "info")
    next_url = request.referrer or url_for("bookings")
    return redirect(next_url)





@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")  # FIX: stops mass account creation
def register():
    if "user_id" in session:
        return redirect(url_for("bookings"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        error = validate_username(username) or validate_password(password)
        if error:
            return render_template("register.html", error=error, username=username)

        hashed = generate_password_hash(password)
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)", (username, hashed))
            db.commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="That username is already taken.", username=username)

        flash("Account registered successfully! You can now log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # FIX: throttles repeated login attempts
def login():
    if "user_id" in session:
        return redirect(url_for("bookings"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        # FIX: verify against the hash instead of comparing plaintext
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"]) if "is_admin" in user.keys() else (user["username"] == "admin")
            flash(f"Welcome back, {user['username']}!", "success")
            if session.get("is_admin"):
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("bookings"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


PAYMENT_STATUSES = ["Pending", "Paid", "Refunded"]
DELIVERY_STATUSES = ["Pending Dispatch", "In Transit", "Delivered", "Delayed"]


def validate_booking_fields(client_name, pickup_location, delivery_location, notes):
    if not client_name or len(client_name) > 100:
        return "Client name is required and must be 100 characters or fewer."
    if not pickup_location or len(pickup_location) > 200:
        return "Pickup location is required and must be 200 characters or fewer."
    if not delivery_location or len(delivery_location) > 200:
        return "Delivery location is required and must be 200 characters or fewer."
    if notes and len(notes) > 500:
        return "Booking notes must be 500 characters or fewer."
    return None


@app.route("/bookings", methods=["GET", "POST"])
def bookings():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()

    error = None
    if request.method == "POST":
        client_name = request.form.get("client_name", "").strip()
        pickup_location = request.form.get("pickup_location", "").strip()
        delivery_location = request.form.get("delivery_location", "").strip()
        notes = request.form.get("notes", "").strip()
        amount_raw = request.form.get("amount", "1850.00").replace(",", "").strip()
        try:
            amount = float(amount_raw) if amount_raw else 1850.00
        except ValueError:
            amount = 1850.00

        error = validate_booking_fields(client_name, pickup_location, delivery_location, notes)
        if not error:
            db.execute(
                """INSERT INTO bookings
                   (user_id, client_name, pickup_location, delivery_location, notes, amount, payment_status, delivery_status)
                   VALUES (?, ?, ?, ?, ?, ?, 'Pending', 'Pending Dispatch')""",
                (session["user_id"], client_name, pickup_location, delivery_location, notes, amount),
            )
            db.commit()
            flash("Booking created successfully!", "success")
            return redirect(url_for("bookings"))
        else:
            flash(error, "error")

    search = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()
    payment_filter = request.args.get("payment", "").strip()

    query = "SELECT * FROM bookings WHERE user_id = ?"
    params = [session["user_id"]]

    if search:
        query += " AND (client_name LIKE ? OR pickup_location LIKE ? OR delivery_location LIKE ?)"
        pattern = f"%{search}%"
        params.extend([pattern, pattern, pattern])

    if status_filter and status_filter in DELIVERY_STATUSES:
        query += " AND delivery_status = ?"
        params.append(status_filter)

    if payment_filter and payment_filter in PAYMENT_STATUSES:
        query += " AND payment_status = ?"
        params.append(payment_filter)

    query += " ORDER BY id DESC"
    all_bookings = db.execute(query, tuple(params)).fetchall()

    # Calculate statistics for the customer dashboard
    stats_rows = db.execute(
        "SELECT payment_status, delivery_status, amount FROM bookings WHERE user_id = ?",
        (session["user_id"],)
    ).fetchall()
    total_count = len(stats_rows)
    in_transit_count = sum(1 for r in stats_rows if r["delivery_status"] == "In Transit")
    delivered_count = sum(1 for r in stats_rows if r["delivery_status"] == "Delivered")
    pending_payment_count = sum(1 for r in stats_rows if r["payment_status"] == "Pending")
    total_spent = sum(r["amount"] or 0 for r in stats_rows if r["payment_status"] == "Paid")

    stats = {
        "total": total_count,
        "in_transit": in_transit_count,
        "delivered": delivered_count,
        "pending_payment": pending_payment_count,
        "total_spent": total_spent,
    }

    return render_template(
        "bookings.html",
        bookings=all_bookings,
        username=session["username"],
        search=search,
        status_filter=status_filter,
        payment_filter=payment_filter,
        stats=stats,
        error=error,
    )


@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if not session.get("is_admin"):
        flash("Admin credentials required. You have been redirected to your Customer Portal.", "error")
        return redirect(url_for("bookings"))

    db = get_db()
    search = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()
    payment_filter = request.args.get("payment", "").strip()

    query = """
        SELECT b.*, u.username as owner_username 
        FROM bookings b 
        JOIN users u ON b.user_id = u.id 
        WHERE 1=1
    """
    params = []
    if search:
        query += " AND (b.client_name LIKE ? OR b.pickup_location LIKE ? OR b.delivery_location LIKE ? OR u.username LIKE ?)"
        pat = f"%{search}%"
        params.extend([pat, pat, pat, pat])

    if status_filter and status_filter in DELIVERY_STATUSES:
        query += " AND b.delivery_status = ?"
        params.append(status_filter)

    if payment_filter and payment_filter in PAYMENT_STATUSES:
        query += " AND b.payment_status = ?"
        params.append(payment_filter)

    query += " ORDER BY b.id DESC"
    all_bookings = db.execute(query, tuple(params)).fetchall()

    # Global KPI metrics
    rev_row = db.execute("SELECT SUM(amount) FROM bookings WHERE payment_status = 'Paid'").fetchone()
    total_rev = rev_row[0] if rev_row and rev_row[0] else 0.0

    users_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] or 0
    total_bookings_count = db.execute("SELECT COUNT(*) FROM bookings").fetchone()[0] or 0
    in_transit_count = db.execute("SELECT COUNT(*) FROM bookings WHERE delivery_status = 'In Transit'").fetchone()[0] or 0
    delivered_count = db.execute("SELECT COUNT(*) FROM bookings WHERE delivery_status = 'Delivered'").fetchone()[0] or 0

    admin_stats = {
        "total_revenue": total_rev,
        "total_users": users_count,
        "total_bookings": total_bookings_count,
        "in_transit": in_transit_count,
        "delivered": delivered_count,
    }

    # Registered clients directory
    clients_rows = db.execute("""
        SELECT u.id, u.username, u.is_admin, u.created_at,
               COUNT(b.id) as total_shipments,
               COALESCE(SUM(CASE WHEN b.payment_status = 'Paid' THEN b.amount ELSE 0 END), 0) as paid_revenue,
               COALESCE(SUM(b.amount), 0) as total_freight_booked,
               MAX(b.created_at) as last_booking_at
        FROM users u
        LEFT JOIN bookings b ON u.id = b.user_id
        GROUP BY u.id, u.username, u.is_admin, u.created_at
        ORDER BY u.id ASC
    """).fetchall()

    return render_template(
        "admin.html",
        bookings=all_bookings,
        clients=clients_rows,
        username=session["username"],
        search=search,
        status_filter=status_filter,
        payment_filter=payment_filter,
        stats=admin_stats,
    )


@app.route("/admin/bookings/<int:booking_id>/status", methods=["POST"])
def admin_update_status(booking_id):
    if "user_id" not in session or not session.get("is_admin"):
        return redirect(url_for("login"))
    payment_status = request.form.get("payment_status", "")
    delivery_status = request.form.get("delivery_status", "")
    if payment_status not in PAYMENT_STATUSES or delivery_status not in DELIVERY_STATUSES:
        flash("Invalid status selection.", "error")
        return redirect(url_for("admin_dashboard"))
    db = get_db()
    db.execute(
        "UPDATE bookings SET payment_status = ?, delivery_status = ? WHERE id = ?",
        (payment_status, delivery_status, booking_id),
    )
    db.commit()
    flash(f"Admin override: Booking #{booking_id} status updated successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/bookings/<int:booking_id>/delete", methods=["POST"])
def admin_delete_booking(booking_id):
    if "user_id" not in session or not session.get("is_admin"):
        return redirect(url_for("login"))
    db = get_db()
    db.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
    db.commit()
    flash(f"Admin deleted shipment #{booking_id} permanently.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/bookings/<int:booking_id>/status", methods=["POST"])
def update_status(booking_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    payment_status = request.form.get("payment_status", "")
    delivery_status = request.form.get("delivery_status", "")
    if payment_status not in PAYMENT_STATUSES or delivery_status not in DELIVERY_STATUSES:
        flash("Invalid status selection.", "error")
        return redirect(url_for("bookings"))
    db = get_db()
    # Ownership check (user_id = ?) stays even here — a user can only
    # update their own bookings, never someone else's by guessing an id.
    cursor = db.execute(
        "UPDATE bookings SET payment_status = ?, delivery_status = ? WHERE id = ? AND user_id = ?",
        (payment_status, delivery_status, booking_id, session["user_id"]),
    )
    db.commit()
    if cursor.rowcount > 0:
        flash(f"Booking #{booking_id} status updated successfully.", "success")
    return redirect(url_for("bookings"))


@app.route("/bookings/<int:booking_id>/edit", methods=["POST"])
def edit_booking(booking_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    client_name = request.form.get("client_name", "").strip()
    pickup_location = request.form.get("pickup_location", "").strip()
    delivery_location = request.form.get("delivery_location", "").strip()
    notes = request.form.get("notes", "").strip()

    error = validate_booking_fields(client_name, pickup_location, delivery_location, notes)
    if error:
        flash(error, "error")
        return redirect(url_for("bookings"))

    db = get_db()
    cursor = db.execute(
        """UPDATE bookings
           SET client_name = ?, pickup_location = ?, delivery_location = ?, notes = ?
           WHERE id = ? AND user_id = ?""",
        (client_name, pickup_location, delivery_location, notes, booking_id, session["user_id"]),
    )
    db.commit()
    if cursor.rowcount > 0:
        flash(f"Booking #{booking_id} details updated.", "success")
    else:
        flash("Unable to update booking.", "error")
    return redirect(url_for("bookings"))


@app.route("/bookings/<int:booking_id>/delete", methods=["POST"])
def delete_booking(booking_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    cursor = db.execute(
        "DELETE FROM bookings WHERE id = ? AND user_id = ?",
        (booking_id, session["user_id"]),
    )
    db.commit()
    if cursor.rowcount > 0:
        flash(f"Booking #{booking_id} deleted successfully.", "success")
    else:
        flash("Could not delete booking.", "error")
    return redirect(url_for("bookings"))


@app.route("/bookings/export")
def export_bookings():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    rows = db.execute(
        """SELECT id, client_name, pickup_location, delivery_location, payment_status, delivery_status, notes, amount, created_at
           FROM bookings WHERE user_id = ? ORDER BY id DESC""",
        (session["user_id"],),
    ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Booking Reference", "Client Name", "Pickup Location", "Delivery Location", "Payment Status", "Delivery Status", "Amount (ZAR)", "Notes", "Created At"])
    for r in rows:
        created = r["created_at"] if "created_at" in r.keys() else ""
        writer.writerow([f"TRK-{r['id']:04d}", r["client_name"], r["pickup_location"], r["delivery_location"], r["payment_status"], r["delivery_status"], r["amount"] or 1850.0, r["notes"] or "", created or ""])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=nari_logistics_manifest.csv"},
    )


@app.route("/track")
def track():
    raw_query = request.args.get("id", "").strip()
    booking = None
    searched = bool(raw_query)

    clean_id = raw_query.upper().replace("TRK-", "").replace("#", "").strip()

    if clean_id.isdigit():
        db = get_db()
        booking = db.execute(
            """SELECT id, client_name, pickup_location, delivery_location, payment_status, delivery_status, notes, amount, created_at
               FROM bookings WHERE id = ?""",
            (int(clean_id),),
        ).fetchone()

    return render_template("track.html", booking=booking, searched=searched, query=raw_query)


if __name__ == "__main__":
    init_db()
    app.run(debug=is_debug_mode())
