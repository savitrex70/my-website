import os
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3, hashlib, re
from functools import wraps

app = Flask(__name__)
# Use environment variable for security; fallback to default for local testing
app.secret_key = os.environ.get("SECRET_KEY", "yoursecretkey")

# ----------------------------
# Database Initialization
# ----------------------------
def init_db():
    with sqlite3.connect("users.db") as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE,
                        email TEXT UNIQUE,
                        password TEXT
                    )''')
        conn.commit()

init_db()

# ----------------------------
# Helper Functions
# ----------------------------
def is_strong_password(password):
    """Check if the password meets strong criteria."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# ----------------------------
# Login Required Decorator
# ----------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("index"))
    return redirect(url_for("login"))

# Registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password_input = request.form["password"]
        confirm = request.form["confirm"]

        # Password checks
        if password_input != confirm:
            return "❌ Passwords do not match."
        if not is_strong_password(password_input):
            return ("❌ Weak password. Minimum 8 chars, including uppercase, lowercase, "
                    "number & special symbol (!@#$%^&* etc.).")

        # Hash the password
        password = hashlib.sha256(password_input.encode()).hexdigest()

        try:
            with sqlite3.connect("users.db") as conn:
                c = conn.cursor()
                c.execute(
                    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, password)
                )
                conn.commit()
        except sqlite3.IntegrityError:
            return "❌ Username or Email already exists."

        return redirect(url_for("login"))

    return render_template("register.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form["username"]
        password_input = request.form["password"]
        password = hashlib.sha256(password_input.encode()).hexdigest()

        with sqlite3.connect("users.db") as conn:
            c = conn.cursor()
            c.execute(
                "SELECT * FROM users WHERE username=? AND password=?",
                (username, password)
            )
            user = c.fetchone()

        if user:
            session["user"] = username
            return redirect(url_for("index"))

        return "❌ Invalid credentials."

    return render_template("login.html")

# Logout
@app.route("/logout")
@login_required
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# Index
@app.route("/index")
@login_required
def index():
    return render_template("index.html", username=session["user"])

# Notes
@app.route("/notes")
@login_required
def notes():
    return render_template("notes.html")

# Projects
@app.route("/projects")
@login_required
def projects():
    return render_template("projects.html")

# Future Plans
@app.route("/future")
@login_required
def future():
    return render_template("future.html")

# Portfolio
@app.route("/portfolio")
@login_required
def portfolio():
    return render_template("portfolio.html")

# Videos
@app.route("/videos")
@login_required
def videos():
    return render_template("videos.html")

# Services
@app.route("/services")
@login_required
def services():
    return render_template("services.html")

# Comments
@app.route("/comments")
@login_required
def comments():
    return render_template("comments.html")

# ----------------------------
# Run App
# ----------------------------
if __name__ == "__main__":
    # Use 0.0.0.0 for online hosting; PORT from environment variable (Render/Heroku)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
