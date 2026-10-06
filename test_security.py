"""
Regression tests proving each fixed vulnerability stays fixed.

Run with:
    pip install pytest
    pytest test_security.py -v

Place this file in the project root (same folder as app.py) before running.
"""
import os
import sqlite3
import subprocess
import sys
import time
import pytest

# app.py refuses to start without SECRET_KEY, so give the test run one
# before importing it.
os.environ.setdefault("SECRET_KEY", "test-only-secret-key")

import app as app_module

APP_DIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Use a throwaway SQLite file per test, never the real vuln.db
    db_path = tmp_path / "test_vuln.db"
    monkeypatch.setattr(app_module, "DB_PATH", str(db_path))

    app_module.app.config["TESTING"] = True
    app_module.app.config["WTF_CSRF_ENABLED"] = False  # off by default; one test re-enables it

    # Rate-limit counts live in shared in-memory storage tied to the app
    # object, which persists across tests in the same pytest run. Reset
    # it here so one test's login attempts don't count against the next.
    app_module.limiter.reset()

    app_module.init_db()

    with app_module.app.test_client() as client:
        yield client


def register(client, username="alice", password="Str0ng!Pass"):
    return client.post(
        "/register",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def login(client, username="alice", password="Str0ng!Pass"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


# --- Vuln 1: SQL injection (login) -----------------------------------------

@pytest.mark.parametrize("payload", [
    "' OR '1'='1",     # classic, but note AND binds tighter than OR
    "' OR 1=1 --",     # comments out the password check: the one that really worked on v0
    "alice' --",       # log in as a known user without the password
])
def test_sql_injection_login_is_blocked(client, payload):
    register(client, "alice", "Str0ng!Pass")

    resp = client.post(
        "/login",
        data={"username": payload, "password": "anything"},
        follow_redirects=True,
    )
    assert b"Invalid credentials" in resp.data
    assert b"Create booking" not in resp.data       # the bookings page marker
    with client.session_transaction() as sess:
        assert "user_id" not in sess                # no session was created


def test_valid_login_reaches_bookings_page(client):
    # Positive control: proves the marker used above really appears on a
    # successful login, so the "not in" assertion can fail when it should.
    register(client, "alice", "Str0ng!Pass")
    resp = login(client, "alice", "Str0ng!Pass")
    assert b"Create booking" in resp.data


# --- Vuln 2: SQL injection (search) -----------------------------------------

def test_sql_injection_search_does_not_leak_other_users_bookings(client):
    register(client, "alice", "Str0ng!Pass")
    login(client, "alice", "Str0ng!Pass")
    client.post(
        "/bookings",
        data={
            "client_name": "Alice Client",
            "pickup_location": "A",
            "delivery_location": "B",
            "notes": "",
        },
    )
    client.get("/logout")

    register(client, "bob", "Str0ng!Pass2")
    login(client, "bob", "Str0ng!Pass2")

    resp = client.get("/bookings?q=' OR '1'='1")
    # Bob's search should never surface Alice's booking
    assert b"Alice Client" not in resp.data


# --- Vuln 3: Stored XSS -----------------------------------------------------

def test_xss_payload_in_notes_is_escaped(client):
    register(client, "alice", "Str0ng!Pass")
    login(client, "alice", "Str0ng!Pass")

    payload = "<script>document.title = 'hacked'</script>"
    resp = client.post(
        "/bookings",
        data={
            "client_name": "Test Client",
            "pickup_location": "A",
            "delivery_location": "B",
            "notes": payload,
        },
        follow_redirects=True,
    )

    assert b"<script>" not in resp.data
    assert b"&lt;script&gt;" in resp.data


# --- Vuln 4: Missing CSRF protection ---------------------------------------

def test_post_without_csrf_token_is_rejected(client):
    app_module.app.config["WTF_CSRF_ENABLED"] = True  # re-enable just for this test

    resp = client.post(
        "/bookings",
        data={
            "client_name": "No CSRF",
            "pickup_location": "A",
            "delivery_location": "B",
            "notes": "",
        },
    )
    assert resp.status_code == 400


# --- Vuln 5: Plaintext password storage -------------------------------------

def test_password_is_hashed_not_plaintext(client):
    register(client, "alice", "Str0ng!Pass")

    db = sqlite3.connect(app_module.DB_PATH)
    row = db.execute("SELECT password FROM users WHERE username = ?", ("alice",)).fetchone()
    db.close()

    stored_password = row[0]
    assert stored_password != "Str0ng!Pass"
    assert stored_password.startswith(("pbkdf2:", "scrypt:"))  # werkzeug hash prefixes

# --- Vuln 7 (extended): rate limits beyond /login ---------------------------

def test_register_is_rate_limited(client):
    statuses = []
    for i in range(12):
        resp = client.post(
            "/register",
            data={"username": f"user{i}", "password": "Str0ng!Pass"},
        )
        statuses.append(resp.status_code)

    assert 429 in statuses
    assert statuses[:10].count(429) == 0  # first 10 per hour are allowed


def test_other_routes_have_a_default_rate_limit(client):
    register(client, "alice", "Str0ng!Pass")
    login(client, "alice", "Str0ng!Pass")

    statuses = [client.get("/bookings").status_code for _ in range(205)]

    assert 429 in statuses  # the 200/hour default eventually kicks in
    # Setup (login redirect) already used a request or two, so only
    # assert the early requests were comfortably allowed.
    assert statuses[:150].count(429) == 0

# --- Vuln 8: Debug mode enabled by default ----------------------------------

def test_debug_mode_is_off_unless_env_var_set(monkeypatch):
    monkeypatch.delenv("FLASK_DEBUG", raising=False)
    assert app_module.is_debug_mode() is False

    monkeypatch.setenv("FLASK_DEBUG", "1")
    assert app_module.is_debug_mode() is True


# --- Vuln 6 (hardened): no hardcoded secret key ------------------------------

def run_app_import(extra_env=None):
    env = {k: v for k, v in os.environ.items()
           if k not in ("SECRET_KEY", "FLASK_DEBUG", "COOKIE_SECURE")}
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, "-c",
         "import app; print('SECURE=' + str(app.app.config['SESSION_COOKIE_SECURE']))"],
        cwd=APP_DIR, env=env, capture_output=True, text=True,
    )


def test_app_refuses_to_start_without_secret_key():
    result = run_app_import()
    assert result.returncode != 0
    assert "SECRET_KEY" in result.stderr


def test_debug_mode_allows_dev_key_and_non_secure_cookie():
    result = run_app_import({"FLASK_DEBUG": "1"})
    assert result.returncode == 0
    assert "SECURE=False" in result.stdout


def test_session_cookie_is_secure_by_default():
    result = run_app_import({"SECRET_KEY": "x" * 32})
    assert result.returncode == 0
    assert "SECURE=True" in result.stdout


# --- Hardening: session cookie flags and security headers --------------------

def test_session_cookie_has_httponly_and_samesite(client):
    register(client, "alice", "Str0ng!Pass")
    resp = client.post("/login", data={"username": "alice", "password": "Str0ng!Pass"})
    cookies = [c for c in resp.headers.getlist("Set-Cookie") if c.startswith("session=")]
    assert cookies, "expected a session cookie after login"
    assert "HttpOnly" in cookies[0]
    assert "SameSite=Lax" in cookies[0]


def test_security_headers_are_present(client):
    resp = client.get("/login")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self'" in csp


# --- Ownership check: a user cannot change another user's booking -----------

def test_user_cannot_update_another_users_booking(client):
    register(client, "alice", "Str0ng!Pass")
    login(client, "alice", "Str0ng!Pass")
    client.post("/bookings", data={
        "client_name": "Alice Client", "pickup_location": "A",
        "delivery_location": "B", "notes": "",
    })
    client.get("/logout")

    register(client, "bob", "Str0ng!Pass2")
    login(client, "bob", "Str0ng!Pass2")
    client.post("/bookings/1/status",
                data={"payment_status": "Paid", "delivery_status": "Delivered"})

    db = sqlite3.connect(app_module.DB_PATH)
    row = db.execute("SELECT payment_status, delivery_status FROM bookings WHERE id = 1").fetchone()
    db.close()
    assert row == ("Pending", "Pending Dispatch")  # unchanged by bob
