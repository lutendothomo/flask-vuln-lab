"""
Regression tests proving each fixed vulnerability stays fixed.

Run with:
    pip install pytest
    pytest test_security.py -v

Place this file in the project root (same folder as app.py) before running.
"""
import os
import sqlite3
import time
import pytest

import app as app_module


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

def test_sql_injection_login_is_blocked(client):
    register(client, "alice", "Str0ng!Pass")

    resp = client.post(
        "/login",
        data={"username": "' OR '1'='1", "password": "anything"},
        follow_redirects=True,
    )
    # Should be bounced back to the login page with an error, never into bookings
    assert b"Invalid credentials" in resp.data
    assert b"Book a delivery" not in resp.data  # adjust if bookings.html heading differs


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


# --- Vuln 7: No brute-force protection --------------------------------------

def test_login_is_rate_limited(client):
    register(client, "alice", "Str0ng!Pass")

    responses = []
    for _ in range(7):
        resp = client.post("/login", data={"username": "alice", "password": "wrong"})
        responses.append(resp.status_code)

    assert 429 in responses  # Flask-Limiter's "Too Many Requests"


# --- Vuln 8: Debug mode enabled by default ----------------------------------

def test_debug_mode_is_off_unless_env_var_set(monkeypatch):
    monkeypatch.delenv("FLASK_DEBUG", raising=False)
    assert app_module.is_debug_mode() is False

    monkeypatch.setenv("FLASK_DEBUG", "1")
    assert app_module.is_debug_mode() is True