# flask-vuln-lab

A small Flask notes app, deliberately built with real security flaws, then
exploited and patched one at a time — a hands-on OWASP Top 10 walkthrough.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\Activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`, register an account, log in, and try adding
and searching notes.

Optional: set a real secret key instead of the local dev fallback —
```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

## Vulnerabilities found

### 1 — SQL injection (login)

**The flaw.** The login query built SQL by directly interpolating user
input into an f-string:
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

**Exploit.** Logging in with the username `' OR '1'='1` and any password
logged in as the first user in the database, bypassing authentication
entirely.

**Impact.** Full authentication bypass.

### 2 — SQL injection (search)

**The flaw.** The notes search box built its query the same unsafe way.

**Exploit.** Searching `' OR '1'='1` returned every note belonging to
every user, not just the logged-in one.

**Impact.** Cross-user data exposure.

### 3 — Stored XSS

**The flaw.** Note bodies were rendered with `| safe`, disabling Jinja2's
auto-escaping.

**Exploit.** A note with body `<script>document.title = "hacked"</script>`
ran that script every time the page loaded.

**Impact.** Stored XSS — any note becomes an attack vector against
whoever views it.

### 4 — Missing CSRF protection

**The flaw.** The add-note form accepted POST requests with no CSRF
token.

**Exploit.** A hidden auto-submitting form on an external page created a
note in a logged-in victim's account just by them visiting that page.

**Impact.** State-changing actions performed without the user's consent.
'''