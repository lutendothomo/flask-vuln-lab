import os
import re
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, session, g
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


app = Flask(__name__)

# FIX: harden session cookie settings. SECURE is tied to whether SECRET_KEY
# is set via env var, so it's off for local dev (plain HTTP) and on once
# deployed with a real secret key (which implies HTTPS in front of it).
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SECRET_KEY") is not None,
)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-fallback-do-not-use-in-production")

# FIX: CSRF protection enabled globally — forms must now include a valid
# csrf_token or their POST requests will be rejected with a 400 error.
csrf = CSRFProtect(app)

# FIX: rate limiting on login to slow down brute-force attempts.
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[])


# FIX: basic security headers on every response.
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

DB_PATH = "vuln.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
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
            password TEXT NOT NULL
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
            payment_status TEXT NOT NULL DEFAULT 'Pending',
            delivery_status TEXT NOT NULL DEFAULT 'Pending Dispatch'
        )
    """)
    db.commit()
    db.close()


@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("bookings"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        error = validate_username(username) or validate_password(password)
        if error:
            return render_template("register.html", error=error, username=username)

        hashed = generate_password_hash(password)
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
            db.commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="That username is already taken.", username=username)

        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # FIX: throttles repeated login attempts
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        # FIX: verify against the hash instead of comparing plaintext
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("bookings"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
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
    if len(notes) > 500:
        return "Booking notes must be 500 characters or fewer."
    return None


@app.route("/bookings", methods=["GET", "POST"])
def bookings():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()

    error = None
    if request.method == "POST":
        client_name = request.form["client_name"].strip()
        pickup_location = request.form["pickup_location"].strip()
        delivery_location = request.form["delivery_location"].strip()
        notes = request.form.get("notes", "").strip()
        error = validate_booking_fields(client_name, pickup_location, delivery_location, notes)
        if not error:
            db.execute(
                """INSERT INTO bookings
                   (user_id, client_name, pickup_location, delivery_location, notes, payment_status, delivery_status)
                   VALUES (?, ?, ?, ?, ?, 'Pending', 'Pending Dispatch')""",
                (session["user_id"], client_name, pickup_location, delivery_location, notes),
            )
            db.commit()

    search = request.args.get("q", "")
    if search:
        like_pattern = f"%{search}%"
        all_bookings = db.execute(
            "SELECT * FROM bookings WHERE user_id = ? AND client_name LIKE ?",
            (session["user_id"], like_pattern),
        ).fetchall()
    else:
        all_bookings = db.execute(
            "SELECT * FROM bookings WHERE user_id = ?", (session["user_id"],)
        ).fetchall()

    return render_template(
        "bookings.html", bookings=all_bookings, username=session["username"], search=search, error=error
    )


@app.route("/bookings/<int:booking_id>/status", methods=["POST"])
def update_status(booking_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    payment_status = request.form.get("payment_status", "")
    delivery_status = request.form.get("delivery_status", "")
    if payment_status not in PAYMENT_STATUSES or delivery_status not in DELIVERY_STATUSES:
        return redirect(url_for("bookings"))
    db = get_db()
    # Ownership check (user_id = ?) stays even here — a user can only
    # update their own bookings, never someone else's by guessing an id.
    db.execute(
        "UPDATE bookings SET payment_status = ?, delivery_status = ? WHERE id = ? AND user_id = ?",
        (payment_status, delivery_status, booking_id, session["user_id"]),
    )
    db.commit()
    return redirect(url_for("bookings"))


def is_debug_mode():
    # FIX (vuln #8): debug mode must be explicitly opted into via an env
    # var, never hardcoded True. Flask's debug mode exposes an interactive
    # in-browser Python console on unhandled errors -- remote code
    # execution if that page is ever reachable outside your own machine.
    return os.environ.get("FLASK_DEBUG", "0") == "1"


if __name__ == "__main__":
    init_db()
    app.run(debug=is_debug_mode())
