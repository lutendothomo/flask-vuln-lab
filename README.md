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