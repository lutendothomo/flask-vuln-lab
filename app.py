import sqlite3
from flask import Flask, request, render_template, redirect, url_for, session, g
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "dev"  # VULN: hardcoded secret key — fix with an env var later

# FIX: CSRF protection enabled globally — forms must now include a valid
# csrf_token or their POST requests will be rejected with a 400 error.
csrf = CSRFProtect(app)

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
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        )
    """)
    db.commit()
    db.close()


@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("notes"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # FIX: hash the password before it's ever stored
        hashed = generate_password_hash(password)
        db = get_db()
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        db.commit()
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
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
            return redirect(url_for("notes"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/notes", methods=["GET", "POST"])
def notes():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()

    if request.method == "POST":
        # VULN: no CSRF token on this form — add flask-wtf protection later
        title = request.form["title"]
        body = request.form["body"]
        db.execute("INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
                   (session["user_id"], title, body))
        db.commit()

    search = request.args.get("q", "")
    if search:
        like_pattern = f"%{search}%"
        all_notes = db.execute(
            "SELECT * FROM notes WHERE user_id = ? AND title LIKE ?",
            (session["user_id"], like_pattern),
        ).fetchall()
    else:
        all_notes = db.execute(
            "SELECT * FROM notes WHERE user_id = ?", (session["user_id"],)
        ).fetchall()

    return render_template("notes.html", notes=all_notes, username=session["username"], search=search)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
