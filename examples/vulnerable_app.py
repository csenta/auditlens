"""
Example target application containing both vulnerable and properly sanitized endpoints.
"""

from flask import Flask, request
import os
import shlex
import sqlite3

app = Flask(__name__)
conn = sqlite3.connect(":memory:", check_same_thread=False)
cursor = conn.cursor()


# 1. Vulnerable: Command Injection
@app.route("/api/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    os.system(f"ping -c 1 {host}")
    return "Ping complete"


# 2. Safe: Sanitized with shlex.quote
@app.route("/api/safe_ping")
def safe_ping():
    host = request.args.get("host", "127.0.0.1")
    escaped_host = shlex.quote(host)
    os.system(f"ping -c 1 {escaped_host}")
    return "Safe ping complete"


# 3. Vulnerable: Raw SQL Interpolation
@app.route("/api/user")
def get_user():
    user_id = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return "User retrieved"


# 4. Safe: Parameterized SQL Query
@app.route("/api/safe_user")
def get_safe_user():
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return "Safe user retrieved"
