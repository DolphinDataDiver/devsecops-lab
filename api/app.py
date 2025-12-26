from flask import Flask, request, jsonify
import sqlite3
import subprocess
import os
import ipaddress
from werkzeug.security import generate_password_hash, check_password_hash
import ast

app = Flask(__name__)

# Load secrets from environment variables
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-secret")
app.config["SECRET_KEY"] = SECRET_KEY

DATABASE = "users.db"
SAFE_READ_DIR = os.path.abspath("data")


# ------------------------
# Database helper
# ------------------------
def get_db():
    return sqlite3.connect(DATABASE)


# ------------------------
# Login (SQL Injection fixed)
# ------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    conn.close()

    if row and check_password_hash(row[0], password):
        return jsonify({"status": "success", "user": username})

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# ------------------------
# Ping (Command Injection fixed)
# ------------------------
@app.route("/ping", methods=["POST"])
def ping():
    data = request.get_json(force=True)
    host = data.get("host", "")

    # Validate IP address (no arbitrary commands)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    try:
        output = subprocess.check_output(
            ["ping", "-c", "1", host],
            stderr=subprocess.STDOUT,
            timeout=5,
        )
    except subprocess.CalledProcessError as e:
        return jsonify({"error": e.output.decode()}), 500

    return jsonify({"output": output.decode()})


# ------------------------
# Compute (eval removed)
# ------------------------
@app.route("/compute", methods=["POST"])
def compute():
    data = request.get_json(force=True)
    expression = data.get("expression", "1+1")

    try:
        # Only allow literals (safe math)
        result = ast.literal_eval(expression)
    except Exception:
        return jsonify({"error": "Invalid expression"}), 400

    return jsonify({"result": result})


# ------------------------
# Secure password hashing
# ------------------------
@app.route("/hash", methods=["POST"])
def hash_password():
    data = request.get_json(force=True)
    password = data.get("password", "")

    hashed = generate_password_hash(password)
    return jsonify({"hash": hashed})


# ------------------------
# Safe file read
# ------------------------
@app.route("/readfile", methods=["POST"])
def readfile():
    data = request.get_json(force=True)
    filename = data.get("filename", "")

    file_path = os.path.abspath(os.path.join(SAFE_READ_DIR, filename))

    # Prevent path traversal
    if not file_path.startswith(SAFE_READ_DIR):
        return jsonify({"error": "Access denied"}), 403

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    return jsonify({"content": content})


# ------------------------
# Debug endpoint removed (secure by default)
# ------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# ------------------------
# Hello
# ------------------------
@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "Welcome to the secure DevSecOps API"})


# ------------------------
# App entrypoint
# ------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

