with open("app.py", encoding="utf-8") as f:
    content = f.read()

old = '''        # VULN: raw string formatting in a SQL query — classic SQL injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = db.execute(query).fetchone()'''
new = '''        # FIX: parameterized query — closes the SQL injection that lived here
        user = db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?", (username, password)
        ).fetchone()'''

assert old in content, "pattern not found"
with open("app.py", "w", encoding="utf-8") as f:
    f.write(content.replace(old, new))
print("patched")