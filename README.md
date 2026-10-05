# flask-vuln-lab

TRACKER = WTC-R2UJGZUS

[![CI](https://github.com/lutendothomo/flask-vuln-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/lutendothomo/flask-vuln-lab/actions)

A small Flask booking app, deliberately built with real security flaws, then exploited and patched one at a time: a hands-on OWASP Top 10 walkthrough.

**Stack:** Python · Flask · SQLite · Flask-WTF · Flask-Limiter · pytest · GitHub Actions

## At a glance

- **8 vulnerabilities** found, exploited and fixed (injection, XSS, CSRF, broken credential storage, secrets, brute force, debug exposure)
- **8 automated regression tests** prove each behavioural fix stays fixed
- **CI on every push:** the test suite plus `pip-audit` (dependency CVEs) and `bandit` (static analysis)
- **Reproducible:** the original vulnerable code is preserved at the git tag `v0-vulnerable`

## Reproduce the exploits

The `main` branch contains the fixed app. To see the original flaws and try the exploits yourself:

```
git checkout v0-vulnerable      # the app before any fix
git checkout main               # back to the fixed version
```

## Setup

```
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\Activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`, register an account, log in, and try adding and searching bookings.

Optional: set a real secret key instead of the local dev fallback:

```
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

## Project structure

```
flask-vuln-lab/
├── .github/workflows/
│   └── ci.yml               # CI: pytest, pip-audit, bandit
├── app.py                   # Flask application (routes, DB access, security fixes)
├── requirements.txt         # Pinned dependencies (Flask, Flask-WTF, Flask-Limiter, ...)
├── test_security.py         # Pytest suite proving each fixed vulnerability stays fixed
├── vuln.db                  # SQLite database (created on first run, gitignored)
├── templates/
│   ├── base.html            # Shared page layout
│   ├── login.html           # Login form
│   ├── register.html        # Registration form
│   └── bookings.html        # Bookings list, search, and add-booking form
├── static/
│   └── style.css            # App styling
└── .gitignore               # Excludes venv/, __pycache__/, vuln.db
```

## Vulnerabilities: found and fixed

| # | Vulnerability | Location | Fix |
|---|---|---|---|
| 1 | SQL injection (login) | `login()` | Parameterized query |
| 2 | SQL injection (search) | `bookings()` | Parameterized query |
| 3 | Stored XSS | `templates/bookings.html` | Auto-escaping restored |
| 4 | Missing CSRF protection | all POST forms | Flask-WTF `CSRFProtect` |
| 5 | Plaintext password storage | `register()` / `login()` | Hashed with Werkzeug |
| 6 | Hardcoded secret key | `app.secret_key` | Read from environment |
| 7 | No brute-force / abuse protection | `login()`, `register()`, all routes | Login 5/min, register 10/hour, 200/hour default elsewhere |
| 8 | Debug mode enabled by default | `app.run()` | Driven by `FLASK_DEBUG`, off unless set |

### 1 & 2: SQL injection

**The flaw.** The login form and the booking search box both built SQL by interpolating user input straight into an f-string:

```
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

**Exploit.** Logging in with the username `' OR '1'='1` and any password made the query match every row, logging the attacker in as the first user without real credentials. The same payload in the search box returned every booking belonging to every user, not just the logged-in one.

**Impact.** Full authentication bypass and cross-user data exposure.

**Fix.** Both queries now use parameterized placeholders (`?`), so user input is always treated as data and never as SQL:

```
user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
```

### 3: Stored XSS

**The flaw.** Booking notes were rendered with Jinja2's `| safe` filter, which switches off HTML auto-escaping:

```
{{ booking['notes'] | safe }}
```

**Exploit.** A booking whose notes were `<script>document.title = "hacked"</script>` ran that script every time the bookings page loaded. In a multi-user app, this is enough to steal session cookies or act as another logged-in user.

**Impact.** Every booking note becomes an attack vector against whoever views it.

**Fix.** The `| safe` filter was removed. Auto-escaping now renders `<script>` as harmless visible text.

### 4: Missing CSRF protection

**The flaw.** The "add booking" form accepted POSTs with no CSRF token.

**Exploit.** A separate page with an auto-submitting form aimed at `/bookings` created a booking in a logged-in victim's account just by being visited.

**Impact.** An attacker can perform state-changing actions as any logged-in user without their consent.

**Fix.** Flask-WTF's `CSRFProtect` is initialised globally and every form carries a hidden `csrf_token`. Requests without a valid token are rejected before the view runs.

### 5: Plaintext password storage

**The flaw.** Passwords were written to the `users` table with no hashing.

**Exploit.** Opening the SQLite file (`sqlite3 vuln.db "SELECT * FROM users;"`) showed every password in cleartext.

**Impact.** One database leak or backup exposure compromises every user's real password, and worse if they reuse it elsewhere.

**Fix.** Passwords are hashed with `werkzeug.security.generate_password_hash` at registration and checked with `check_password_hash` at login. The raw password is never stored.

### 6: Hardcoded secret key

**The flaw.** `app.secret_key = "dev"` was committed to the repo. Flask signs session cookies with this key, so anyone who knows it can forge valid sessions.

**Fix.** The key is read from the `SECRET_KEY` environment variable, with a clearly labelled dev-only fallback so the app still runs locally.

### 7: No brute-force or abuse protection

**The flaw.** No endpoint had a rate limit: unlimited login guesses, unlimited account creation, every route open to hammering.

**Fix.** Flask-Limiter enforces three tiers per IP: `/login` 5 per minute, `/register` 10 per hour, everything else 200 per hour.

### 8: Debug mode enabled by default

**The flaw.** `app.run(debug=True)` was hardcoded. Flask's debug mode serves an interactive Python console on unhandled exceptions. If that page is ever reachable by anyone but you, it is remote code execution.

**Impact.** Full server compromise if debug mode is ever live outside a local machine.

**Fix.** Debug mode is driven by the `FLASK_DEBUG` environment variable and is off unless set. Use `FLASK_DEBUG=1` locally if you want the debugger.

## Tests

```
pip install pytest
python -m pytest test_security.py -v
```

`test_security.py` proves each fix holds, rather than just claiming it here:

| Test | Proves |
|---|---|
| `test_sql_injection_login_is_blocked` | Vuln 1: SQLi payload in the login form no longer bypasses auth |
| `test_sql_injection_search_does_not_leak_other_users_bookings` | Vuln 2: SQLi payload in search can't surface another user's data |
| `test_xss_payload_in_notes_is_escaped` | Vuln 3: `<script>` in notes renders as escaped text, not executable markup |
| `test_post_without_csrf_token_is_rejected` | Vuln 4: POSTs without a valid CSRF token are rejected |
| `test_password_is_hashed_not_plaintext` | Vuln 5: stored passwords are hashed |
| `test_register_is_rate_limited` | Vuln 7: account creation is throttled after 10 requests/hour |
| `test_other_routes_have_a_default_rate_limit` | Vuln 7: routes without a specific limit still hit the 200/hour default |
| `test_debug_mode_is_off_unless_env_var_set` | Vuln 8: debug mode stays off unless explicitly enabled |

Vuln 6 (the hardcoded secret key) has no test, because it is a property of the source code and not something observable through the app's behaviour at runtime.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

- **test:** the full pytest suite
- **audit:** `pip-audit` against `requirements.txt` and `bandit` static analysis. It reports findings without failing the build badge.

CI has already paid off once: `pip-audit` flagged `pytest` (PYSEC-2026-1845, affecting 9.0.2 and earlier), and the pin was raised to 9.0.3.

## Dependency scan

Pinned versions were first checked by hand against public CVE records. `pip-audit` now runs in CI as well.

| Package | Version | Result |
|---|---|---|
| Werkzeug | 3.1.8 | Clear. [CVE-2026-21860](https://www.sentinelone.com/vulnerability-database/cve-2026-21860/) (path traversal via Windows device names in `safe_join`) only affects versions **before 3.1.5**. |
| Jinja2 | 3.1.6 | Clear. [CVE-2024-34064](https://github.com/advisories/GHSA-h75v-3vvj-5mfj) (XSS via the `xmlattr` filter) affects **3.1.3 and earlier**, fixed in 3.1.4. |
| pytest | 9.0.3 | `pip-audit` flagged 9.0.2 (PYSEC-2026-1845) in CI; fixed by upgrading to 9.0.3. |
| Flask | 3.1.3 | No known CVEs found for this version. |
| Flask-WTF | 1.3.0 | No known CVEs found for this version. |
| WTForms | 3.2.2 | No known CVEs found for this version. |
| MarkupSafe | 3.0.3 | No known CVEs found for this version. |
| itsdangerous | 2.2.0 | No known CVEs found for this version. |
| Flask-Limiter | latest resolved | No known CVEs found. |

## Known limitations

- **Rate limits are in memory.** Counters reset on restart and are tracked per worker process. A shared store such as Redis would be the production answer.
- **The secret-key fallback is still a weakness.** The dev-only fallback keeps the app runnable locally, but a production deployment should fail to start if `SECRET_KEY` is unset.
- **This is a learning project, not a hardened product.** It runs on Flask's development server and is not intended to be deployed.