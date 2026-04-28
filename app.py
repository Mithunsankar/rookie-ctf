import os
import sqlite3
from functools import wraps

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["FLAG"] = os.environ.get("FLAG", "flag{ssti_username_unlocked}")

DATABASE = os.path.join(app.instance_path, "rookie_ctf.db")


def get_db():
    os.makedirs(app.instance_path, exist_ok=True)
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )
        schema = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'"
        ).fetchone()
        if schema and "UNIQUE" in schema["sql"].upper():
            conn.execute("ALTER TABLE users RENAME TO users_old")
            conn.execute(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                INSERT INTO users (id, username, password_hash)
                SELECT id, username, password_hash FROM users_old
                """
            )
            conn.execute("DROP TABLE users_old")
        conn.commit()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Log in first to enter the challenge room.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def current_user():
    if "user_id" not in session:
        return None

    with get_db() as conn:
        return conn.execute(
            "SELECT id, username FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()


@app.before_request
def ensure_database():
    init_db()


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("home"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("register.html")

        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            conn.commit()

        flash("Registration complete. Log in to continue.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            users = conn.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchall()

        user = next(
            (
                candidate
                for candidate in users
                if check_password_hash(candidate["password_hash"], password)
            ),
            None,
        )

        if user is None:
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/home")
@login_required
def home():
    user = current_user()
    if user is None:
        session.clear()
        return redirect(url_for("login"))

    # Intentional CTF vulnerability: the username is treated as a Jinja template.
    # Registering as {{7*7}} should render the greeting as 49.
    rendered_username = render_template_string(user["username"])

    videos = [
        "https://www.youtube.com/embed/S7MNX_UD7vY",
        "https://www.youtube.com/embed/iWoiwFRLV4I",
        "https://www.youtube.com/embed/8ev9ZX9J45A",
        "https://www.youtube.com/embed/xfqjYcFAZ9E",
    ]

    return render_template(
        "home.html",
        rendered_username=rendered_username,
        raw_username=user["username"],
        videos=videos,
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
