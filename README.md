# NARI Logistics — Enterprise Cargo & Dispatch Management System

TRACKER = WTC-R2UJGZUS

[![CI](https://github.com/lutendothomo/flask-vuln-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/lutendothomo/flask-vuln-lab/actions)

> 🦬 **Symbol of Unstoppable Power:** Inspired by the African Cape Buffalo, NARI Logistics delivers resilient cargo coordination, live telemetry tracking, and enterprise-grade dispatch manifests across southern Africa and worldwide corridors.
> 
> ⚠️ The `v0-vulnerable` tag preserves the intentionally insecure educational walkthrough. The `main` branch is the fully secured, modernized enterprise web application.

---

## Platform Highlights

- **Distinct Dual Portals (RBAC):**
  - **Administrator Master Console (`/admin`):** Global fleet telemetry, system-wide revenue accounting in active currency, shipment deletion and status overrides, and a dedicated **Registered Clients Directory** featuring client account roles, total cargo shipments, and paid tariffs.
  - **Customer Portal (`/bookings`):** Client-isolated booking manifests, inline status updater, declared cargo valuations, interactive modal editor, and CSV export.
- **Cape Buffalo Branding & Ethereal Zero-Blue Aesthetic:**
  - **Buffalo Head Emblem:** Featured in brand navigation and footer, replacing generic icons.
  - **Full Cape Buffalo Artwork:** Showcased prominently on both `/login` and `/register` portals.
  - **Zero-Blue Color Palette:** Deep obsidian plum surfaces (`#0e0417`, `#160824`), luminous light lilac (`#D4A8E9`), radiant orchid mauve (`#FAACFA`), and pastel bubblegum pink (`#FFA8F4`).
- **Dynamic Multi-Currency System:**
  - **South African Rand Default (`ZAR`, `R`):** Tailored for South African and pan-African logistics corridors.
  - Real-time conversion switchable to **USD ($)**, **EUR (€)**, and **GBP (£)** via navigation selector.
- **Public Live Radar Tracker (`/track`):**
  - Instant cargo lookup by reference (`#TRK-0001` or raw ID) with a 4-milestone visual dispatch timeline (*Order Placed → Warehouse Dispatch → In Transit → Final Delivery*).
- **Hardened Security Architecture:**
  - 8 OWASP Top 10 vulnerabilities comprehensively patched.
  - **17 automated pytest security & regression tests** passing 100%.

---

## Quickstart & Setup

### 1. Environment & Dependencies

```bash
# Clone the repository
git clone https://github.com/lutendothomo/flask-vuln-lab.git
cd flask-vuln-lab

# Create and activate Python virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows PowerShell: .\venv\Scripts\Activate.ps1

# Install runtime and development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 2. Configuration & Launch

The application refuses to start without a cryptographically secure `SECRET_KEY`.

#### Windows (PowerShell):
```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:COOKIE_SECURE = "0"        # For local HTTP testing
python -c "import app; app.init_db(); app.app.run(port=5000)"
```

#### macOS / Linux:
```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export COOKIE_SECURE=0          # For local HTTP testing
python3 -c "import app; app.init_db(); app.app.run(port=5000)"
```

*Development Shortcut:* Running with `$env:FLASK_DEBUG="1"` enables the built-in dev key and non-Secure cookies for local debugging.

### 3. Default Credentials & Role Switching


- **Role Switcher:** When testing locally, click the role pill badge (`Admin` / `Customer`) in the navigation bar to instantaneously toggle between Customer Portal and Admin Console views.

---

## 🐳 Docker Deployment

```bash
# Build non-root production container
docker build -t nari-logistics .

# Run container (mapped to port 8000)
docker run --rm -p 8000:8000 \
  -e SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))") \
  -e COOKIE_SECURE=0 \
  nari-logistics
```

---

## 🛡️ Security Audit & Vulnerabilities Patched

| # | Vulnerability Category | Affected Endpoint | Mitigation Applied |
|---|---|---|---|
| 1 | SQL Injection (Auth) | `/login` | Parameterized SQLite queries (`?`) preventing auth bypass |
| 2 | SQL Injection (Search) | `/bookings` | Parameterized search filter matching client name, route, or notes |
| 3 | Stored Cross-Site Scripting (XSS) | `templates/bookings.html` | Removed unsafe filter; Jinja2 auto-escaping enforced |
| 4 | Missing CSRF Protection | All state-changing POST forms | Global Flask-WTF `CSRFProtect` with per-form tokens |
| 5 | Plaintext Credential Storage | `users` DB table | Werkzeug `generate_password_hash` with secure salting |
| 6 | Hardcoded Application Secrets | `app.secret_key` | Mandatory `SECRET_KEY` environment variable enforcement |
| 7 | Brute Force & Rate Limit Deficiencies | `/login`, `/register`, global | IP rate limiting: login 5/min, register 10/hr, global 200/hr |
| 8 | Unintended Debug Console Exposure | `app.run()` | Debugger gated strictly behind `FLASK_DEBUG=1` |
| + | Ownership & RBAC Violations | `/bookings/<id>/status` | Strict ownership checks (`user_id = session['user_id']`); Admin isolated |
| + | Hardened Response Headers | Global responses | Content-Security-Policy (CSP), X-Frame-Options (`DENY`), X-Content-Type-Options (`nosniff`) |

---

##  Automated Test Suite

Run the full pytest suite:

```bash
python -m pytest test_security.py -v
```



## Project Architecture

```text
flask-vuln-lab/
├── app.py                   # Core Flask app (routes, DB migrations, multi-currency, RBAC)
├── test_security.py         # 17-point regression & security test suite
├── Dockerfile               # Non-root production container deployment
├── requirements.txt         # Runtime requirements
├── requirements-dev.txt     # Test dependencies
├── vuln.db                  # Local SQLite database (schema migrated automatically)
├── static/
│   ├── style.css            # Zero-Blue design tokens, glassmorphism, responsive styles
│   ├── app.js               # Client controllers (modals, password toggle, auto-fade flash)
│   └── img/
│       ├── buffalo_head_dark.png # Buffalo head logo emblem
│       └── buffalo_full.png      # Full Cape buffalo artwork for auth screens
└── templates/
    ├── base.html            # Navigation with buffalo logo, currency switch, flash banners
    ├── landing.html         # Visitor portal with live tracker search & fleet metrics
    ├── bookings.html        # Customer dispatch portal (CRUD, cards, CSV export)
    ├── admin.html           # Administrator Console & Registered Clients Directory
    ├── track.html           # Public parcel radar & 4-step route timeline
    ├── login.html           # Split auth view featuring full Cape Buffalo illustration
    └── register.html        # Registration portal with real-time password checklist
```

---

## License & Acknowledgments

This project is open-source under the [MIT License](LICENSE). Built for educational security benchmarking and modern Python web application design.
