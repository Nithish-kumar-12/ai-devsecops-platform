import zipfile
import os

zip_filename = "sample_codebase.zip"

files = {
    "app/main.py": """import sqlite3

# Secret Detection: Leaked AWS credential
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuv"

def get_user(db, user_id):
    # SAST: SQL Injection flaw
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

def render_comment(comment):
    # SAST: Potential XSS flaw
    return f"<div>{comment}</div>"
""",
    "requirements.txt": """requests==2.28.1
urllib3==1.26.4
flask==1.1.2
""",
    "package.json": """{
  "name": "sample-vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.15",
    "axios": "0.21.1"
  }
}
"""
}

with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zf:
    for filename, content in files.items():
        zf.writestr(filename, content)

print(f"Successfully generated {zip_filename} ({os.path.getsize(zip_filename)} bytes)")
