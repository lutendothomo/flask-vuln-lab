# flask-vuln-lab

A small Flask app, deliberately built with real security flaws, then
exploited and patched one at a time — a hands-on OWASP Top 10 walkthrough.
It started as a notes app and was later rebuilt into a small logistics
"bookings" tool (NARI Logistics) on top of the same hardened codebase.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\Activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`, register an account, log in, and try creating
and updating bookings.

Optional: set a real secret key instead of the local dev fallback —
```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

## Vulnerabilities: what was found, and what was fixed

| # | Vulnerability | Location | Status |
|---|----------------|----------|--------|
| 1 | SQL injection (login) | `login()` | Fixed — parameterized query |
| 2 | SQL injection (search) | `notes()` (now `bookings()`) | Fixed — parameterized query |
| 3 | Stored XSS | `templates/notes.html` (now `bookings.html`) | Fixed — auto-escaping restored |
| 4 | Missing CSRF protection | all POST forms | Fixed — Flask-WTF `CSRFProtect` |
| 5 | Plaintext password storage | `register()` / `login()` | Fixed — hashed with Werkzeug |
| 6 | Hardcoded secret key | `app.secret_key` | Fixed — read from environment |
| 7 | No brute-force protection | `login()` | Fixed — rate limited to 5/min |

### 1 & 2 — SQL injection

**The flaw.** Both the login form and the notes search box built SQL queries
by directly interpolating user input into an f-string:

```python
query = f"SELECT * FROM users WHERE username = \'{username}\' AND password = \'{password}\'"
```

**Exploit.** Logging in with the username


and any password caused the query to evaluate to `WHERE username = '' OR
'1'='1' AND password = '...'`, which matches every row in the table — this
logs the attacker in as the first user in the database without knowing any
real credentials. The same trick against the search box (`' OR '1'='1`)
returned every note belonging to every user, not just the logged-in one,
via the injected `OR` condition.

**Impact.** Full authentication bypass, and cross-user data exposure through
the search endpoint.

**Fix.** Both queries now use parameterized placeholders (`?`), so user
input is always treated as data, never as part of the SQL statement:

```python
user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
```

### 3 — Stored XSS

**The flaw.** Note bodies were rendered with Jinja2\'s `| safe` filter,
which explicitly disables Jinja2\'s default HTML auto-escaping:

```html
{{ note[\'body\'] | safe }}
```

**Exploit.** Creating a note with the body

```html
<script>document.title = "hacked"</script>
```

ran the script every time the notes page loaded — proof that arbitrary
HTML/JS submitted by a user was being executed in another viewer\'s browser.
In a multi-user app this is enough to steal session cookies or perform
actions as another logged-in user.

**Impact.** Stored cross-site scripting — any note becomes an attack
vector against whoever views it.

**Fix.** The `| safe` filter was removed. Jinja2\'s default auto-escaping
now converts `<script>` into harmless, visibly-displayed text instead of
executable markup.

### 4 — Missing CSRF protection

**The flaw.** The "add note" form accepted POST requests with no CSRF
token, so a malicious external page could submit a hidden form to
`/notes` on a logged-in user\'s behalf and they\'d never know.

**Exploit.** A separate HTML page with an auto-submitting form pointed at
`http://127.0.0.1:5000/notes` successfully created a note in the victim\'s
account when they merely visited that page while already logged in — no
interaction beyond loading the page was required.

**Impact.** An attacker can perform state-changing actions as any logged-in
user without their consent.

**Fix.** `Flask-WTF`\'s `CSRFProtect` is now initialized globally, and every
form includes a hidden `csrf_token` field. Requests without a valid,
matching token are rejected before the view function even runs.

### 5 — Plaintext password storage

**The flaw.** Passwords were written straight into the `users` table with
no hashing at all — anyone with read access to `vuln.db` could read every
password in plain text.

**Exploit.** Opening the SQLite file directly (`sqlite3 vuln.db "SELECT *
FROM users;"`) showed every stored password in cleartext.

**Impact.** A single database leak or backup exposure compromises every
user\'s real password — worse still if they reuse it elsewhere.

**Fix.** Passwords are hashed with `werkzeug.security.generate_password_hash`
on registration and verified with `check_password_hash` on login. The raw
password is never stored.

### 6 — Hardcoded secret key

**The flaw.** `app.secret_key = "dev"` was committed straight into the
source code, visible to anyone who can read the repo. Flask uses this key
to sign session cookies, so a known key lets an attacker forge valid
sessions.

**Fix.** The key is now read from the `SECRET_KEY` environment variable,
with a clearly-labeled dev-only fallback so the app still runs locally
without extra setup.

### 7 — No brute-force protection

**The flaw.** The login endpoint accepted unlimited attempts per second,
making automated password guessing practical.

**Fix.** `Flask-Limiter` now caps `/login` at 5 attempts per minute per IP
address.

## Dependency scan

`pip-audit` was the intended tool for this, but it wouldn\'t install cleanly
in this environment (pip\'s resolver kept timing out and falling back to
building a very old `CacheControl` release from source). Rather than lose
more time fighting a local build issue, the pinned versions in
`requirements.txt` were checked manually against public CVE records instead:

| Package | Version | Result |
|---|---|---|
| Werkzeug | 3.1.8 | Clear. [CVE-2026-21860](https://www.sentinelone.com/vulnerability-database/cve-2026-21860/) (path traversal via Windows device names in `safe_join`) only affects versions **before 3.1.5** — this project is on 3.1.8, already past the fix. |
| Jinja2 | 3.1.6 | Clear. [CVE-2024-34064](https://github.com/advisories/GHSA-h75v-3vvj-5mfj) (XSS via the `xmlattr` filter) affects **3.1.3 and earlier**, fixed in 3.1.4 — this project is on 3.1.6. |
| Flask | 3.1.3 | No known CVEs found for this version. |
| Flask-WTF | 1.3.0 | No known CVEs found for this version. |
| WTForms | 3.2.2 | No known CVEs found for this version. |
| MarkupSafe | 3.0.3 | No known CVEs found for this version. |
| itsdangerous | 2.2.0 | No known CVEs found for this version. |
| Flask-Limiter | (latest resolved) | No known CVEs found. |

If `pip-audit` becomes available later (e.g. run from a different machine
or network), it\'s still worth running as a second check — this manual
review only covers the vulnerabilities that turned up in a public CVE
search, not the full audit an automated tool would do.

## Running the exploits yourself

The commits before the "Patch vulnerabilities" commit in this repo\'s
history contain the original, unpatched code, if you want to reproduce any
of the exploits above against that version directly.
