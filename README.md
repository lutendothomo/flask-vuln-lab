# flask-vuln-lab

TRACKER = WTC-R2UJGZUS

[![CI](https://github.com/lutendothomo/flask-vuln-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/lutendothomo/flask-vuln-lab/actions)

> ⚠️ The `v0-vulnerable` tag is intentionally insecure. Run it locally only and never deploy or expose it.

A small Flask booking app, deliberately built with real security flaws, then exploited and patched one at a time: a hands-on OWASP Top 10 walkthrough.

**Stack:** Python · Flask · SQLite · Flask-WTF · Flask-Limiter · pytest · GitHub Actions

## At a glance

- **8 vulnerabilities** found, exploited and fixed (injection, XSS, CSRF, broken credential storage, secrets, brute force, debug exposure)
- **17 automated tests:** regression tests for every fix, plus checks on cookie flags, security headers, record ownership and secure start-up.
- **CI on every push and weekly:** tests, `pip-audit` (dependency CVEs), `bandit` (static analysis), and a Docker image build with a Trivy scan
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
```

The app **refuses to start without a secret key**. For local use, set one and turn off the HTTPS-only cookie flag (browsers only send `Secure` cookies over HTTPS):

```
# macOS / Linux
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export COOKIE_SECURE=0
python app.py
```

```
# Windows PowerShell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:COOKIE_SECURE = "0"
python app.py
```

Shortcut for development only: `FLASK_DEBUG=1 python app.py` uses a built-in dev key and non-Secure cookies, but also turns on Flask's interactive debugger, so never use it on a machine other people can reach.

Open `http://127.0.0.1:5000`, register an account, log in, and try adding and searching bookings. Passwords need 5-64 characters with an upper-case letter, a lower-case letter, a number and a special character.

## Run in Docker

```
docker build -t flask-vuln-lab .
docker run --rm -p 8000:8000 -e SECRET_KEY=<long-random-value> -e COOKIE_SECURE=0 flask-vuln-lab
```

Use `COOKIE_SECURE=0` only when testing over plain `http://`; behind HTTPS leave it unset. The container runs as a non-root user under gunicorn with one worker (rate-limit counters are in memory), and its SQLite file is lost when the container is removed.

## Project structure

```
flask-vuln-lab/
├── .github/workflows/
│   └── ci.yml               # CI: tests, pip-audit, bandit, Docker build + Trivy
├── app.py                   # Flask application (routes, DB access, security fixes)
├── requirements.txt         # Pinned runtime dependencies
├── requirements-dev.txt     # Runtime + pytest
├── test_security.py         # Pytest suite proving the fixes (and hardening) hold
├── Dockerfile               # Non-root image served by gunicorn
├── .dockerignore
├── LICENSE
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
| 6 | Hardcoded secret key | `app.secret_key` | Read from environment; the app refuses to start without it |
| 7 | No brute-force / abuse protection | `login()`, `register()`, all routes | Login 5/min, register 10/hour, 200/hour default elsewhere |
| 8 | Debug mode enabled by default | `app.run()` | Driven by `FLASK_DEBUG`, off unless set |

### 1 & 2: SQL injection

**The flaw.** The login form and the booking search box both built SQL by interpolating user input straight into an f-string:

```
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

**Exploit.** Logging in with the username `' OR 1=1 --` and any password turned the query into `... WHERE username = '' OR 1=1 --' AND password = '...'`. The `--` comments out the password check, so every row matches and the attacker is logged in as the first user without real credentials. (The textbook `' OR '1'='1` does *not* work against this query: `AND` binds tighter than `OR`, so the password condition still applies. Payloads that comment out the rest of the query, like this one or `alice' --`, are what bypass it.) In the search box, a payload ending in `OR 1=1 --` returned every booking belonging to every user, not just the logged-in one.

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

**Fix.** The key is read from the `SECRET_KEY` environment variable. There is no fallback: the app raises an error at start-up if the variable is missing, unless `FLASK_DEBUG=1` is set for local development. Tests cover both paths.

### 7: No brute-force or abuse protection

**The flaw.** No endpoint had a rate limit: unlimited login guesses, unlimited account creation, every route open to hammering.

**Fix.** Flask-Limiter enforces three tiers per IP: `/login` 5 per minute, `/register` 10 per hour, everything else 200 per hour.

### 8: Debug mode enabled by default

**The flaw.** `app.run(debug=True)` was hardcoded. Flask's debug mode serves an interactive Python console on unhandled exceptions. If that page is ever reachable by anyone but you, it is remote code execution.

**Impact.** Full server compromise if debug mode is ever live outside a local machine.

**Fix.** Debug mode is driven by the `FLASK_DEBUG` environment variable and is off unless set. Use `FLASK_DEBUG=1` locally if you want the debugger.

### Also in place: hardening beyond the 8 flaws

- **Session cookie flags:** `HttpOnly`, `SameSite=Lax`, and `Secure` by default.
- **Security headers on every response:** `Content-Security-Policy` (`default-src 'self'`, `base-uri 'none'`, `form-action 'self'`, `frame-ancestors 'none'`), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.
- **Server-side input validation:** username and password rules, and length limits on booking fields.
- **Ownership checks:** a user can only read and update their own bookings, never someone else's by guessing an ID.

## Tests

```
pip install -r requirements-dev.txt
python -m pytest test_security.py -v
```

`test_security.py` sets a throwaway `SECRET_KEY` itself, so no environment setup is needed. It proves each fix holds, rather than just claiming it here:

| Test | Proves |
|---|---|
| `test_sql_injection_login_is_blocked` (3 payloads) | Vuln 1: injection payloads in the login form no longer bypass auth or create a session |
| `test_valid_login_reaches_bookings_page` | Positive control: the success marker used above really appears on a valid login |
| `test_sql_injection_search_does_not_leak_other_users_bookings` | Vuln 2: SQLi payload in search can't surface another user's data |
| `test_xss_payload_in_notes_is_escaped` | Vuln 3: `<script>` in notes renders as escaped text, not executable markup |
| `test_post_without_csrf_token_is_rejected` | Vuln 4: POSTs without a valid CSRF token are rejected |
| `test_password_is_hashed_not_plaintext` | Vuln 5: stored passwords are hashed |
| `test_app_refuses_to_start_without_secret_key` | Vuln 6: no secret key, no start-up |
| `test_debug_mode_allows_dev_key_and_non_secure_cookie` | Vuln 6/8: the dev opt-out works only with `FLASK_DEBUG=1` |
| `test_register_is_rate_limited` | Vuln 7: account creation is throttled after 10 requests/hour |
| `test_other_routes_have_a_default_rate_limit` | Vuln 7: routes without a specific limit still hit the 200/hour default |
| `test_debug_mode_is_off_unless_env_var_set` | Vuln 8: debug mode stays off unless explicitly enabled |
| `test_session_cookie_is_secure_by_default` | Cookies are `Secure` unless explicitly relaxed |
| `test_session_cookie_has_httponly_and_samesite` | Session cookie carries `HttpOnly` and `SameSite=Lax` |
| `test_security_headers_are_present` | CSP, `X-Frame-Options` and `nosniff` are sent |
| `test_user_cannot_update_another_users_booking` | Ownership check: another user's booking stays unchanged |

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request, and weekly (Mondays) so newly published CVEs turn the badge red even when nobody has pushed:

- **test:** the full pytest suite
- **audit:** `pip-audit` against the pinned requirements, then `bandit` static analysis
- **image:** builds the Docker image, smoke-tests that it serves the login page, checks that it refuses to start without `SECRET_KEY`, then scans it with Trivy (HIGH/CRITICAL, fixable findings only)

CI has already paid off twice: `pip-audit` flagged `pytest` (PYSEC-2026-1845, affecting 9.0.2 and earlier) and later `Werkzeug` 3.1.8 (CVE-2026-102598, as reported by pip-audit; fixed in 3.1.9), and both pins were raised.

## Dependency scan

Every pinned version is checked by `pip-audit` in CI. Notes on individual packages:

| Package | Version | Result |
|---|---|---|
| Werkzeug | 3.1.9 | `pip-audit` flagged 3.1.8 (CVE-2026-102598); fixed by upgrading to 3.1.9. [CVE-2026-21860](https://www.sentinelone.com/vulnerability-database/cve-2026-21860/) (path traversal via Windows device names in `safe_join`) only affects versions **before 3.1.5**. |
| Jinja2 | 3.1.6 | Clear. [CVE-2024-34064](https://github.com/advisories/GHSA-h75v-3vvj-5mfj) (XSS via the `xmlattr` filter) affects **3.1.3 and earlier**, fixed in 3.1.4. |
| pytest | 9.0.3 | `pip-audit` flagged 9.0.2 (PYSEC-2026-1845) in CI; fixed by upgrading to 9.0.3. |
| Flask, Flask-WTF, WTForms, MarkupSafe, itsdangerous, Flask-Limiter | pinned | No known vulnerabilities reported by `pip-audit`. |

## Known limitations

- **Rate limits are in memory and per IP.** Counters reset on restart and are tracked per worker process, which is why the container runs a single worker. A shared store such as Redis would be the production answer. Behind a proxy, the client IP needs configuring (`ProxyFix`) or all users share one limit.
- **No account lockout, MFA or password reset.** Brute-force protection is the per-IP rate limit only.
- **`/logout` is a GET request.** It can be triggered cross-site (logout CSRF). Low impact, but a POST would be better.
- **SQLite and no persistent volume in Docker.** Fine for a learning project, not for real data.
- **This is a learning project, not a hardened product.** It is not intended to be exposed to the internet.
