
import os
import re
import uuid
import sqlite3
import secrets
from datetime import timedelta
from contextlib import contextmanager
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    jsonify,
    session,
    url_for
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename


# =====================================================
# FLASK CONFIGURATION
# =====================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "UNICHAT_SECRET_KEY"
) or secrets.token_hex(32)

app.permanent_session_lifetime = timedelta(days=7)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get(
        "COOKIE_SECURE", "0"
    ) == "1",
    MAX_CONTENT_LENGTH=3 * 1024 * 1024,
    UPLOAD_FOLDER=os.path.join(
        app.root_path,
        "static",
        "uploads",
        "profile"
    )
)

DATABASE = os.path.join(app.root_path, "polytechnic_hub.db")

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
ALLOWED_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    "image/webp"
}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


# =====================================================
# DATABASE CONNECTION
# =====================================================

def get_db():

    conn = sqlite3.connect(
        DATABASE,
        timeout=15
    )

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")

    return conn


@contextmanager
def database():

    conn = get_db()

    try:
        yield conn
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# =====================================================
# DATABASE INITIALIZATION
# =====================================================

def initialize_database():

    with database() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                name TEXT NOT NULL,

                username TEXT NOT NULL UNIQUE,

                mobile TEXT NOT NULL UNIQUE,

                email TEXT UNIQUE,

                dob TEXT NOT NULL,

                gender TEXT NOT NULL,

                state TEXT NOT NULL,

                district TEXT NOT NULL,

                college TEXT NOT NULL,

                course TEXT NOT NULL,

                branch TEXT NOT NULL,

                semester TEXT NOT NULL,

                bio TEXT DEFAULT '',

                profile_photo TEXT DEFAULT '',

                password TEXT NOT NULL,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP

            )
        """)

        # Add missing columns to an older users table.
        existing_columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        }

        optional_columns = {
            "email": "TEXT",
            "dob": "TEXT DEFAULT ''",
            "gender": "TEXT DEFAULT ''",
            "state": "TEXT DEFAULT ''",
            "district": "TEXT DEFAULT ''",
            "college": "TEXT DEFAULT ''",
            "course": "TEXT DEFAULT ''",
            "branch": "TEXT DEFAULT ''",
            "semester": "TEXT DEFAULT ''",
            "bio": "TEXT DEFAULT ''",
            "profile_photo": "TEXT DEFAULT ''",
            "created_at": "TEXT"
        }

        for column, definition in optional_columns.items():

            if column not in existing_columns:

                conn.execute(
                    f"ALTER TABLE users ADD COLUMN {column} {definition}"
                )

        # Real chat records.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chats (

                id TEXT PRIMARY KEY,

                owner_user_id INTEGER NOT NULL,

                name TEXT NOT NULL,

                photo TEXT DEFAULT '',

                last_message TEXT DEFAULT '',

                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,

                unread_count INTEGER DEFAULT 0,

                is_online INTEGER DEFAULT 0,

                chat_type TEXT DEFAULT 'personal',

                is_favourite INTEGER DEFAULT 0,

                FOREIGN KEY(owner_user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE

            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_chats_owner_timestamp
            ON chats(owner_user_id, timestamp)
        """)

    print("UniChat Database Initialized Successfully")


# =====================================================
# SECURITY HELPERS
# =====================================================

def api_error(message, status=400):

    return jsonify({
        "success": False,
        "message": message
    }), status


def login_required_api(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            return api_error("Authentication required.", 401)

        return func(*args, **kwargs)

    return wrapper


def verify_csrf():

    token = request.headers.get("X-CSRF-Token", "")

    saved_token = session.get("_csrf_token", "")

    return (
        bool(token)
        and bool(saved_token)
        and secrets.compare_digest(token, saved_token)
    )


def allowed_file(filename):

    if not filename or "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    return extension in ALLOWED_EXTENSIONS


def validate_mobile(mobile):

    return bool(
        mobile and re.fullmatch(r"[0-9]{10}", mobile)
    )


def validate_username(username):

    return bool(
        username
        and re.fullmatch(r"[a-z0-9_.]{3,20}", username)
    )


def delete_uploaded_file(filename):

    if not filename:
        return

    path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        app.logger.exception("Unable to remove uploaded file")


def get_profile_photo(filename):

    if not filename:
        return ""

    return url_for(
        "static",
        filename=f"uploads/profile/{filename}"
    )


# =====================================================
# HOME PAGE
# =====================================================

@app.route("/")
def index():

    if "user_id" in session:
        return redirect(url_for("home_page"))

    return render_template("index.html")


# =====================================================
# LOGIN PAGE
# =====================================================

@app.route("/login")
@app.route("/login.html")
def login_page():

    if "user_id" in session:
        return redirect(url_for("home_page"))

    return render_template("login.html")


# =====================================================
# HOME DASHBOARD
# =====================================================

@app.route("/home.html")
@app.route("/dashboard")
def home_page():

    if "user_id" not in session:
        return redirect(url_for("login_page"))

    return render_template("home.html")


# =====================================================
# API STATUS
# =====================================================

@app.route("/api/status", methods=["GET"])
def api_status():

    return jsonify({

        "status": "running",
        "backend": "Python Flask",
        "database": "SQLite",
        "project": "UniChat"

    })


# =====================================================
# CSRF TOKEN API
# =====================================================

@app.route("/api/csrf", methods=["GET"])
@login_required_api
def csrf_token():

    token = session.get("_csrf_token")

    if not token:

        token = secrets.token_urlsafe(32)

        session["_csrf_token"] = token

    return jsonify({
        "csrfToken": token
    })


# =====================================================
# USER REGISTRATION
# =====================================================

@app.route("/register", methods=["POST"])
def register():

    uploaded_filename = None

    try:

        # -----------------------------
        # GET FORM DATA
        # -----------------------------

        full_name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()
        email = request.form.get("email", "").strip().lower()

        dob = request.form.get("dob", "").strip()
        gender = request.form.get("gender", "").strip()

        state = request.form.get("state", "").strip()
        district = request.form.get("district", "").strip()

        college = request.form.get("college", "").strip()
        course = request.form.get("course", "").strip()
        branch = request.form.get("branch", "").strip()
        semester = request.form.get("semester", "").strip()

        bio = request.form.get("bio", "").strip()
        password = request.form.get("password", "")

        # -----------------------------
        # REQUIRED FIELD VALIDATION
        # -----------------------------

        required_fields = [
            full_name,
            username,
            mobile,
            dob,
            gender,
            state,
            district,
            college,
            course,
            branch,
            semester,
            password
        ]

        if not all(required_fields):

            return api_error("Please fill all required fields.")

        if len(full_name) > 100:
            return api_error("Name is too long.")

        if not validate_username(username):
            return api_error("Invalid username format.")

        if not validate_mobile(mobile):
            return api_error("Enter a valid 10 digit mobile number.")

        if email and len(email) > 254:
            return api_error("Email is too long.")

        if len(password) < 6:
            return api_error("Password must contain at least 6 characters.")

        if len(password) > 128:
            return api_error("Password is too long.")

        if gender not in ("Male", "Female", "Other"):
            return api_error("Invalid gender selection.")

        if len(bio) > 500:
            return api_error("Bio must be below 500 characters.")

        # -----------------------------
        # PROFILE PHOTO VALIDATION
        # -----------------------------

        photo = request.files.get("photo")

        if photo and photo.filename:

            if not allowed_file(photo.filename):
                return api_error("Unsupported image format.")

            if photo.mimetype not in ALLOWED_MIME_TYPES:
                return api_error("Invalid image content type.")

            photo.stream.seek(0, os.SEEK_END)
            photo_size = photo.stream.tell()
            photo.stream.seek(0)

            if photo_size > 2 * 1024 * 1024:
                return api_error("Profile photo must be below 2MB.")

            extension = secure_filename(
                photo.filename
            ).rsplit(".", 1)[1].lower()

            uploaded_filename = (
                str(uuid.uuid4()) + "." + extension
            )

            photo.save(
                os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    uploaded_filename
                )
            )

        # -----------------------------
        # PASSWORD HASH
        # -----------------------------

        hashed_password = generate_password_hash(password)

        # -----------------------------
        # INSERT USER
        # -----------------------------

        with database() as conn:

            cursor = conn.execute("""

                INSERT INTO users (

                    name,
                    username,
                    mobile,
                    email,
                    dob,
                    gender,
                    state,
                    district,
                    college,
                    course,
                    branch,
                    semester,
                    bio,
                    profile_photo,
                    password

                )

                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

            """, (

                full_name,
                username,
                mobile,
                email or None,
                dob,
                gender,
                state,
                district,
                college,
                course,
                branch,
                semester,
                bio,
                uploaded_filename or "",
                hashed_password

            ))

            user_id = cursor.lastrowid

        uploaded_filename = None

        return jsonify({

            "success": True,
            "message": "Registration Successful",
            "user_id": user_id

        }), 201

    except sqlite3.IntegrityError:

        delete_uploaded_file(uploaded_filename)

        return api_error(
            "Username, mobile number or email already exists.",
            409
        )

    except Exception:

        delete_uploaded_file(uploaded_filename)

        app.logger.exception("Registration failed")

        return api_error(
            "Registration failed. Please try again.",
            500
        )


# =====================================================
# USER LOGIN
# =====================================================

@app.route("/login", methods=["POST"])
def login():

    try:

        mobile = request.form.get("mobile", "").strip()

        password = request.form.get("password", "")

        if not validate_mobile(mobile) or not password:

            return api_error("Invalid mobile number or password.", 400)

        with database() as conn:

            user = conn.execute("""

                SELECT *
                FROM users
                WHERE mobile = ?

            """, (mobile,)).fetchone()

        if user is None:

            return api_error("Invalid mobile number or password.", 401)

        if not check_password_hash(
            user["password"],
            password
        ):

            return api_error("Invalid mobile number or password.", 401)

        # -----------------------------
        # REGENERATE SESSION
        # -----------------------------

        session.clear()

        session.permanent = True

        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["username"] = user["username"]
        session["mobile"] = user["mobile"]
        session["photo"] = user["profile_photo"]

        # Generate CSRF token.
        session["_csrf_token"] = secrets.token_urlsafe(32)

        return jsonify({

            "success": True,

            "message": "Login Successful",

            "redirect": "home.html"

        })

    except Exception:

        app.logger.exception("Login failed")

        return api_error(
            "Unable to login. Please try again.",
            500
        )


# =====================================================
# AUTHENTICATED USER PROFILE API
# =====================================================

@app.route("/api/me", methods=["GET"])
@login_required_api
def get_current_user():

    try:

        with database() as conn:

            user = conn.execute("""

                SELECT
                    id,
                    name,
                    username,
                    mobile,
                    email,
                    dob,
                    gender,
                    state,
                    district,
                    college,
                    course,
                    branch,
                    semester,
                    bio,
                    profile_photo

                FROM users
                WHERE id = ?

            """, (session["user_id"],)).fetchone()

        if user is None:

            session.clear()

            return api_error("User account not found.", 401)

        return jsonify({

            "success": True,

            "user": {

                "id": user["id"],

                "fullName": user["name"],

                "username": user["username"],

                "mobile": user["mobile"],

                "email": user["email"],

                "dob": user["dob"],

                "gender": user["gender"],

                "state": user["state"],

                "district": user["district"],

                "college": user["college"],

                "course": user["course"],

                "branch": user["branch"],

                "semester": user["semester"],

                "bio": user["bio"],

                "photoURL": get_profile_photo(
                    user["profile_photo"]
                )

            }

        })

    except Exception:

        app.logger.exception("Profile loading failed")

        return api_error("Unable to load profile.", 500)


# =====================================================
# AUTHENTICATED CHAT LIST API
# =====================================================

@app.route("/api/chats", methods=["GET"])
@login_required_api
def get_chats():

    try:

        with database() as conn:

            rows = conn.execute("""

                SELECT
                    id,
                    name,
                    photo,
                    last_message,
                    timestamp,
                    unread_count,
                    is_online,
                    chat_type,
                    is_favourite

                FROM chats

                WHERE owner_user_id = ?

                ORDER BY timestamp DESC

                LIMIT 100

            """, (session["user_id"],)).fetchall()

        chats = []

        for row in rows:

            chats.append({

                "id": row["id"],

                "name": row["name"],

                "photo": row["photo"],

                "lastMessage": row["last_message"],

                "timestamp": row["timestamp"],

                "unreadCount": row["unread_count"],

                "isOnline": bool(row["is_online"]),

                "type": row["chat_type"],

                "isFavourite": bool(row["is_favourite"])

            })

        return jsonify({

            "success": True,

            "chats": chats

        })

    except Exception:

        app.logger.exception("Chat loading failed")

        return api_error("Unable to load chats.", 500)


# =====================================================
# CHECK LOGIN
# =====================================================

@app.route("/check-login", methods=["GET"])
def check_login():

    if "user_id" not in session:

        return jsonify({
            "logged_in": False
        }), 401

    return jsonify({

        "logged_in": True,

        "name": session.get("name"),

        "username": session.get("username"),

        "photo": get_profile_photo(
            session.get("photo")
        )

    })


# =====================================================
# SECURE LOGOUT
# =====================================================

@app.route("/logout", methods=["POST"])
@login_required_api
def logout():

    if not verify_csrf():

        return api_error(
            "Invalid CSRF token.",
            403
        )

    session.clear()

    response = jsonify({

        "success": True,

        "message": "Logged out successfully."

    })

    response.headers["Cache-Control"] = "no-store"

    return response


# =====================================================
# ERROR HANDLERS
# =====================================================

@app.errorhandler(413)
def file_too_large(error):

    return api_error(
        "Uploaded file is too large.",
        413
    )


@app.errorhandler(404)
def page_not_found(error):

    if request.path.startswith("/api/"):
        return api_error("API endpoint not found.", 404)

    return "Page not found", 404


@app.after_request
def security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["X-Frame-Options"] = "DENY"

    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    response.headers["Cache-Control"] = "no-store"

    return response


# =====================================================
# START SERVER
# =====================================================

if __name__ == "__main__":

    initialize_database()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
