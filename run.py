from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_from_directory,
    jsonify,
    send_file,
)
from database import init_db, get_db_connection, is_postgres
from supabase_storage import (
    is_storage_configured,
    upload_document_to_supabase,
    download_document_from_supabase,
    create_signed_download_url,
    delete_document_from_supabase,
    ensure_bucket_exists,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from pathlib import Path
from dotenv import load_dotenv
from io import BytesIO
import hashlib
import os
import uuid
import secrets
import logging

# ---------------- LOGGING & CONFIGURATION ----------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Fallback secret key (stable across all workers)
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "trustvault-production-stable-secret-key-2026-auth-secure"
)

# Robust Session Cookie Settings for cloud reverse proxies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=86400,
)

UPLOAD_FOLDER = BASE_DIR / "private_uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "png", "jpg", "jpeg"}
MAX_FILE_SIZE = 5 * 1024 * 1024

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

# Initialize database schema safely
try:
    init_db()
    if is_storage_configured():
        ensure_bucket_exists()
except Exception as e:
    logger.error(f"Initialization notice: {e}")


# ---------------- CSRF PROTECTION ----------------

def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

app.jinja_env.globals["csrf_token"] = generate_csrf_token


@app.before_request
def csrf_protect():
    if app.config.get("TESTING") and not app.config.get("WTF_CSRF_ENABLED", True):
        return
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        # Allow internal JSON API endpoints
        if request.path.startswith("/api/"):
            return
        token = session.get("_csrf_token")
        form_token = request.form.get("csrf_token")
        if not token or not form_token or not secrets.compare_digest(token, form_token):
            log_audit(
                action="CSRF_VIOLATION",
                status="DENIED",
                details=f"CSRF verification failed on {request.path}"
            )
            return "CSRF verification failed. Please refresh the page and try again.", 403


# ---------------- AUDIT LOGGING HELPER ----------------

def log_audit(action, document_name=None, status="SUCCESS", details=None):
    """Safely records security and document events into the audit_logs table."""
    user_id = session.get("user_id")
    ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip_addr and "," in ip_addr:
        ip_addr = ip_addr.split(",")[0].strip()

    try:
        conn = get_db_connection()
        conn.execute(
            """
            INSERT INTO audit_logs (user_id, action, document_name, status, ip_address, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, action, document_name, status, ip_addr, details),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Audit log recording error: {e}")


# ---------------- ACCESS CONTROL DECORATORS & HELPERS ----------------

def extract_user_id(user_row):
    """Safely extracts integer user id from any database row format (RealDictRow, sqlite3.Row, tuple, dict)."""
    if not user_row:
        return None
    # 1. Dict-like or RealDictRow get()
    if hasattr(user_row, "get"):
        for k in ("id", "user_id", "ID", "USER_ID", "Id"):
            val = user_row.get(k)
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    pass
    # 2. Key lookups
    if hasattr(user_row, "keys"):
        keys = list(user_row.keys())
        for k in keys:
            if str(k).lower() in ("id", "user_id"):
                val = user_row[k]
                if val is not None:
                    try:
                        return int(val)
                    except (ValueError, TypeError):
                        pass
        if keys:
            val = user_row[keys[0]]
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    pass
    # 3. Tuple or sequence index
    try:
        val = user_row[0]
        if val is not None:
            return int(val)
    except Exception:
        pass
    return None


def extract_field(user_row, field_name, default=""):
    """Safely extracts a string field from any database row format."""
    if not user_row:
        return default
    if hasattr(user_row, "get"):
        for k in (field_name, field_name.lower(), field_name.upper()):
            val = user_row.get(k)
            if val is not None:
                return str(val)
    if hasattr(user_row, "keys"):
        for k in list(user_row.keys()):
            if str(k).lower() == field_name.lower():
                val = user_row[k]
                if val is not None:
                    return str(val)
    return default


def get_current_user_id():
    """Returns current user's integer ID, self-healing from username if session is partially populated."""
    user_id = session.get("user_id")
    if user_id is not None:
        try:
            return int(user_id)
        except (ValueError, TypeError):
            pass

    username = session.get("username")
    if username:
        conn = get_db_connection()
        try:
            u = conn.execute("SELECT id, username FROM users WHERE LOWER(username) = LOWER(?)", (username,)).fetchone()
            if u:
                uid = extract_user_id(u)
                if uid is not None:
                    session["user_id"] = uid
                    return uid
        except Exception as e:
            logger.error(f"Error self-healing user session: {e}")
        finally:
            conn.close()
    return None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not get_current_user_id():
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not get_current_user_id():
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            log_audit(
                action="UNAUTHORIZED_ADMIN_ACCESS",
                status="DENIED",
                details=f"User {session.get('username')} attempted to access {request.path}"
            )
            return "Access denied: Admins only.", 403
        return view(*args, **kwargs)

    return wrapped


# ---------------- HEALTH CHECK ----------------

@app.route("/health")
def health_check():
    """Health check endpoint for Render deployment monitoring."""
    cols = []
    user_sample = None
    conn = get_db_connection()
    is_pg = is_postgres(conn)
    try:
        if is_pg:
            c = conn.execute("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users'").fetchall()
            cols = [dict(r) for r in c]
        else:
            c = conn.execute("PRAGMA table_info(users)").fetchall()
            cols = [dict(r) for r in c]
        u = conn.execute("SELECT * FROM users LIMIT 1").fetchone()
        if u:
            user_sample = {k: (str(v)[:30] if k == 'password_hash' else v) for k, v in dict(u).items()}
    except Exception as e:
        cols = str(e)
    finally:
        conn.close()

    return jsonify({
        "status": "healthy",
        "app": "TrustVault",
        "database": "postgresql" if is_pg else "sqlite",
        "storage": "supabase" if is_storage_configured() else "local",
        "users_columns": cols,
        "user_sample": user_sample
    }), 200


# ---------------- HOME ----------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------- USER REGISTRATION HELPER ----------------

def register_new_user(full_name, raw_email, raw_username, password, confirm_password=None):
    """
    Unified validation and account creation helper for TrustVault.
    Accepts full name, email, optional username, and password.
    Ensures safe uniqueness checks, prevents crashes, and returns (error_msg, user_row).
    """
    full_name = (full_name or "").strip()
    raw_email = (raw_email or "").strip()
    raw_username = (raw_username or "").strip()
    password = password or ""

    if confirm_password is not None and confirm_password != password:
        return "Passwords do not match. Please verify and try again.", None

    if len(password) < 8:
        return "Password must have at least 8 characters.", None

    # Handle cases where username was entered as an email or vice-versa
    if not raw_email and "@" in raw_username:
        raw_email = raw_username
        raw_username = ""
    elif not raw_username and not ("@" in raw_email):
        raw_username = raw_email
        raw_email = ""

    if not raw_email and not raw_username:
        return "Please enter an email address or username.", None

    email = raw_email.lower() if raw_email else None
    if email and ("@" not in email or "." not in email):
        return "Please enter a valid email address (e.g. user@example.com).", None

    conn = get_db_connection()
    try:
        # 1. Check if email is already taken
        if email:
            existing_email = conn.execute(
                "SELECT id FROM users WHERE email IS NOT NULL AND LOWER(email) = LOWER(?)",
                (email,),
            ).fetchone()
            if existing_email:
                return "An account with this email address already exists. Please log in.", None

        # 2. Determine and verify unique username
        if raw_username:
            username = raw_username.strip()
            if len(username) < 3:
                return "Username must have at least 3 characters.", None
            existing_user = conn.execute(
                "SELECT id FROM users WHERE LOWER(username) = LOWER(?)",
                (username,),
            ).fetchone()
            if existing_user:
                return "This username is already taken. Please choose another username.", None
        else:
            # Derive safe unique username from email
            base_user = email.split("@")[0].strip()
            if len(base_user) < 3:
                base_user = f"user_{base_user}"

            existing_user = conn.execute(
                "SELECT id FROM users WHERE LOWER(username) = LOWER(?)",
                (base_user,),
            ).fetchone()
            if not existing_user:
                username = base_user
            elif len(email) <= 100 and not conn.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (email,)).fetchone():
                username = email
            else:
                import random
                username = f"{base_user[:85]}_{random.randint(1000, 9999)}"

        display_name = full_name if full_name else (email.split("@")[0] if email else username)

        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, email, full_name)
            VALUES (?, ?, 'user', ?, ?)
            """,
            (username, generate_password_hash(password), email, display_name),
        )
        conn.commit()

        new_user = conn.execute(
            "SELECT id, username, role, email, full_name FROM users WHERE LOWER(username) = LOWER(?)",
            (username,),
        ).fetchone()

        log_audit(action="REGISTER", status="SUCCESS", details=f"User registered: {username} ({email or 'no email'})")
        return None, new_user

    except Exception as e:
        conn.rollback()
        logger.error(f"register_new_user error: {e}")
        err_msg = str(e).lower()
        if "unique" in err_msg or "duplicate" in err_msg:
            return "This username or email is already taken. Please choose another.", None
        return f"Registration error: {str(e)[:120]}", None
    finally:
        conn.close()


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
@app.route("/register.html", methods=["GET", "POST"])
def register():
    if get_current_user_id():
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":
        full_name = request.form.get("fullName") or request.form.get("name") or request.form.get("full_name") or ""
        email = request.form.get("email", "")
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirmPassword") or request.form.get("confirm_password")

        err, new_user = register_new_user(full_name, email, username, password, confirm_password)
        if err:
            error = err
            log_audit(action="REGISTER_FAILED", status="DENIED", details=f"Registration failed for {email or username}: {err}")
        else:
            session.clear()
            session.permanent = True
            uid = extract_user_id(new_user)
            session["user_id"] = uid
            session["username"] = extract_field(new_user, "username")
            session["full_name"] = extract_field(new_user, "full_name", session["username"])
            session["role"] = extract_field(new_user, "role", "user")
            generate_csrf_token()
            return redirect(url_for("dashboard"))

    return render_template("register.html", error=error)


# ---------------- LOGIN & LOGOUT ----------------

@app.route("/login", methods=["GET", "POST"])
@app.route("/login.html", methods=["GET", "POST"])
def login():
    if get_current_user_id():
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":
        identifier = (request.form.get("username", "") or request.form.get("email", "")).strip()
        password = request.form.get("password", "")

        if not identifier or not password:
            error = "Please enter both your email/username and password."
        else:
            connection = get_db_connection()
            try:
                # Case-insensitive query matches username OR email
                user = connection.execute(
                    """
                    SELECT id, username, email, full_name, password_hash, role
                    FROM users
                    WHERE LOWER(username) = LOWER(?) OR (email IS NOT NULL AND LOWER(email) = LOWER(?))
                    """,
                    (identifier, identifier),
                ).fetchone()

                if not user:
                    log_audit(action="LOGIN_FAILED", status="DENIED", details=f"Identifier not found: {identifier}")
                    error = f"Account '{identifier}' not found. Please click 'Create an account' below to register first, or use demo / Password123!"
                elif not check_password_hash(extract_field(user, "password_hash"), password):
                    log_audit(action="LOGIN_FAILED", status="DENIED", details=f"Wrong password for: {identifier}")
                    error = "Incorrect password. Please verify and try again."
                else:
                    session.clear()
                    session.permanent = True
                    uid = extract_user_id(user)
                    session["user_id"] = uid
                    session["username"] = extract_field(user, "username", identifier)
                    session["full_name"] = extract_field(user, "full_name", session["username"])
                    session["role"] = extract_field(user, "role", "user")
                    generate_csrf_token()

                    log_audit(action="LOGIN", status="SUCCESS", details=f"User logged in: {identifier}")
                    return redirect(url_for("dashboard"))
            except Exception as e:
                logger.error(f"Login error: {e}")
                error = f"Login notice: {str(e)[:120]}"
                log_audit(action="LOGIN_ERROR", status="DENIED", details=str(e))
            finally:
                connection.close()

    return render_template("login.html", error=error, registered=request.args.get("registered"))


@app.route("/logout")
def logout():
    username = session.get("username")
    log_audit(action="LOGOUT", status="SUCCESS", details=f"User logged out: {username}")
    session.clear()
    return redirect(url_for("home"))


# ---------------- REST API AUTH ENDPOINTS (REFERENCE SPEC) ----------------

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or request.form or {}
    full_name = data.get("fullName") or data.get("full_name") or data.get("name") or ""
    email = data.get("email") or ""
    username = data.get("username") or ""
    password = data.get("password") or ""
    confirm_password = data.get("confirmPassword") or data.get("confirm_password")

    err, user_row = register_new_user(full_name, email, username, password, confirm_password)
    if err:
        return jsonify({"ok": False, "message": err}), 400

    return jsonify({
        "ok": True,
        "message": "Account created successfully!",
        "username": extract_field(user_row, "username"),
        "fullName": extract_field(user_row, "full_name")
    }), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or request.form or {}
    identifier = (data.get("email") or data.get("username") or "").strip()
    password = data.get("password") or ""

    if not identifier or not password:
        return jsonify({"ok": False, "message": "Email or username and password are required."}), 400

    conn = get_db_connection()
    try:
        user = conn.execute(
            """
            SELECT id, username, email, full_name, password_hash, role
            FROM users
            WHERE LOWER(username) = LOWER(?) OR (email IS NOT NULL AND LOWER(email) = LOWER(?))
            """,
            (identifier, identifier),
        ).fetchone()
    finally:
        conn.close()

    if not user:
        log_audit(action="LOGIN_FAILED", status="DENIED", details=f"API identifier not found: {identifier}")
        return jsonify({"ok": False, "message": f"Account '{identifier}' not found. Please click 'Create Account' to register first."}), 404

    if not check_password_hash(extract_field(user, "password_hash"), password):
        log_audit(action="LOGIN_FAILED", status="DENIED", details=f"Wrong password for: {identifier}")
        return jsonify({"ok": False, "message": "Incorrect password. Please verify and try again."}), 401

    session.clear()
    session.permanent = True
    uid = extract_user_id(user)
    session["user_id"] = uid
    session["username"] = extract_field(user, "username", identifier)
    session["full_name"] = extract_field(user, "full_name", session["username"])
    session["role"] = extract_field(user, "role", "user")
    generate_csrf_token()

    log_audit(action="LOGIN", status="SUCCESS", details=f"User logged in via API: {identifier}")
    return jsonify({
        "ok": True,
        "message": "Login successful. Opening your workspace...",
        "user": {
            "id": uid,
            "username": session["username"],
            "fullName": session.get("full_name") or session["username"],
            "role": session["role"],
        }
    }), 200


@app.route("/api/auth/me", methods=["GET"])
def api_auth_me():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401
    return jsonify({
        "id": user_id,
        "username": session.get("username"),
        "fullName": session.get("full_name") or session.get("username", "TrustVault User"),
        "role": session.get("role", "user")
    }), 200


@app.route("/api/logout", methods=["GET", "POST"])
def api_logout():
    username = session.get("username")
    log_audit(action="LOGOUT", status="SUCCESS", details=f"User logged out via API: {username}")
    session.clear()
    return jsonify({"ok": True, "message": "Logged out successfully"}), 200


# ---------------- PROFILE & PASSWORD CHANGE ----------------

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    message = None
    error = None
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")

        if len(new_password) < 8:
            error = "New password must have at least 8 characters."
        else:
            conn = get_db_connection()
            try:
                user = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
                if not user or not check_password_hash(user["password_hash"], current_password):
                    error = "Current password does not match."
                    log_audit(action="PASSWORD_CHANGE_FAILED", status="DENIED")
                else:
                    new_hash = generate_password_hash(new_password)
                    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
                    conn.commit()
                    message = "Password updated successfully."
                    log_audit(action="PASSWORD_CHANGE", status="SUCCESS")
            finally:
                conn.close()

    return render_template("profile.html", message=message, error=error)


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
@app.route("/dashboard.html")
@login_required
def dashboard():
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    conn = get_db_connection()
    try:
        is_admin = session.get("role") == "admin"

        # Count owned documents
        doc_count = conn.execute(
            "SELECT COUNT(*) as count FROM documents WHERE owner_id = ?",
            (user_id,)
        ).fetchone()["count"]

        # Count shared documents
        shared_count = conn.execute(
            "SELECT COUNT(*) as count FROM document_permissions WHERE user_id = ?",
            (user_id,)
        ).fetchone()["count"]

        # Admin statistics
        admin_stats = {}
        if is_admin:
            total_users = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()["count"]
            total_docs = conn.execute("SELECT COUNT(*) as count FROM documents").fetchone()["count"]
            total_shares = conn.execute("SELECT COUNT(*) as count FROM document_permissions").fetchone()["count"]
            admin_stats = {
                "total_users": total_users,
                "total_docs": total_docs,
                "total_shares": total_shares,
            }
    finally:
        conn.close()

    return render_template(
        "dashboard.html",
        doc_count=doc_count,
        shared_count=shared_count,
        admin_stats=admin_stats
    )


# ---------------- ACCESS CONTROL & FILE INTEGRITY INFO ----------------

@app.route("/access-control")
@login_required
def access_control():
    return render_template("access_control.html")


@app.route("/file-integrity")
@login_required
def file_integrity():
    return render_template("file_integrity.html")


# ---------------- AI ASSISTANT ----------------

@app.route("/ai-assistant")
@login_required
def ai_assistant():
    return render_template("ai_assistant.html")


@app.route("/api/chat", methods=["POST"])
@login_required
def ai_chat():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    if not isinstance(message, str):
        return jsonify({"error": "Invalid message format."}), 400

    message = message.strip()

    if not message:
        return jsonify({"error": "Please enter a message."}), 400

    if len(message) > 1000:
        return jsonify({"error": "Message must be 1000 characters or fewer."}), 400

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return jsonify({
            "error": "AI is not configured. Check your .env file."
        }), 503

    try:
        from google import genai
        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model="gemini-3.5-flash-lite",
            contents=(
                "You are TrustVault's AI security assistant. "
                "Answer questions about document security, access control, "
                "password safety, SHA-256 integrity checks, and the "
                "TrustVault application. Be clear and helpful. "
                "Never request passwords or API keys. "
                "You cannot access the application's private files or "
                "database. Do not ask users to submit confidential documents.\n\n"
                f"User question: {message}"
            ),
        )

        answer = response.text
        if not answer:
            return jsonify({"error": "The AI returned an empty response. Please try again."}), 502

        return jsonify({"answer": answer})

    except Exception as e:
        app.logger.exception("Gemini API request failed")
        return jsonify({
            "error": f"Gemini error: {type(e).__name__}: {str(e)[:300]}"
        }), 502


# ---------------- LIST DOCUMENTS (OWNED & SHARED) ----------------

@app.route("/documents")
@app.route("/documents.html")
@login_required
def documents():
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    category_filter = request.args.get("category", "").strip()
    search_query = request.args.get("q", "").strip()
    message = request.args.get("message", "").strip() or request.args.get("error", "").strip() or None

    connection = get_db_connection()
    try:
        # 1. Fetch Owned Documents
        owned_query = "SELECT * FROM documents WHERE owner_id = ?"
        params = [user_id]

        if category_filter:
            owned_query += " AND category = ?"
            params.append(category_filter)

        if search_query:
            owned_query += " AND original_name LIKE ?"
            params.append(f"%{search_query}%")

        owned_query += " ORDER BY id DESC"
        owned_files = connection.execute(owned_query, tuple(params)).fetchall()

        # 2. Fetch Shared Documents (where user is Viewer/Editor)
        shared_query = """
            SELECT d.*, p.id AS permission_id, p.permission, u.username AS owner_name
            FROM documents d
            JOIN document_permissions p ON d.id = p.document_id
            JOIN users u ON d.owner_id = u.id
            WHERE p.user_id = ?
        """
        shared_params = [user_id]

        if category_filter:
            shared_query += " AND d.category = ?"
            shared_params.append(category_filter)

        if search_query:
            shared_query += " AND d.original_name LIKE ?"
            shared_params.append(f"%{search_query}%")

        shared_query += " ORDER BY d.id DESC"
        shared_files = connection.execute(shared_query, tuple(shared_params)).fetchall()

        # 3. Fetch active permissions for owned documents (for sharing management)
        owned_ids = [f["id"] for f in owned_files]
        shares_by_doc = {}
        if owned_ids:
            # Fetch users shared with
            shares = connection.execute(
                """
                SELECT p.id, p.document_id, p.permission, p.created_at, u.username
                FROM document_permissions p
                JOIN users u ON p.user_id = u.id
                WHERE p.document_id IN ({})
                """.format(",".join("?" * len(owned_ids))),
                tuple(owned_ids)
            ).fetchall()
            for s in shares:
                shares_by_doc.setdefault(s["document_id"], []).append(s)

        # 4. Fetch all other users for the sharing dropdown
        all_users = connection.execute(
            "SELECT id, username FROM users WHERE id != ? ORDER BY username ASC",
            (user_id,)
        ).fetchall()

    finally:
        connection.close()

    return render_template(
        "documents.html",
        files=owned_files,
        shared_files=shared_files,
        shares_by_doc=shares_by_doc,
        all_users=all_users,
        current_category=category_filter,
        search_query=search_query,
        message=message
    )


# ---------------- UPLOAD DOCUMENT (SUPABASE STORAGE) ----------------

@app.route("/documents/upload", methods=["GET", "POST"])
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_document():
    if request.method == "GET":
        return redirect(url_for("documents"))

    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    uploaded_file = request.files.get("document")
    category = request.form.get("category", "General").strip() or "General"

    if not uploaded_file or not uploaded_file.filename:
        return redirect(url_for("documents"))

    safe_name = secure_filename(uploaded_file.filename)
    if not safe_name or "." not in safe_name:
        return "Invalid filename. Please upload a file with an extension.", 400

    extension = safe_name.rsplit(".", 1)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        return "File type not allowed. Supported: PDF, TXT, DOCX, PNG, JPG.", 400

    content = uploaded_file.read(MAX_FILE_SIZE + 1)
    if not content or len(content) > MAX_FILE_SIZE:
        return "File is empty or exceeds the 5 MB limit.", 400

    # 1. Compute SHA-256 integrity hash
    file_hash = hashlib.sha256(content).hexdigest()
    file_size = len(content)

    # 2. Server-generated unique object path and filename
    stored_name = f"{uuid.uuid4().hex}.{extension}"
    storage_path = f"documents/{user_id}/{stored_name}"

    # 3. Upload to Supabase Storage if configured; otherwise use resilient local fallback
    use_supabase = is_storage_configured()
    storage_provider = "local"
    if use_supabase:
        content_type = uploaded_file.content_type or "application/octet-stream"
        success, err = upload_document_to_supabase(
            file_bytes=content,
            storage_path=storage_path,
            original_filename=safe_name,
            content_type=content_type,
        )
        if success:
            storage_provider = "supabase"
        else:
            logger.warning(
                f"Supabase Storage upload returned ({err}). Gracefully saving to local vault storage so upload succeeds."
            )
            log_audit(
                action="STORAGE_FALLBACK",
                document_name=safe_name,
                status="SUCCESS",
                details=f"Supabase note: {err}; saved to local storage",
            )
            local_path = UPLOAD_FOLDER / stored_name
            local_path.write_bytes(content)
            use_supabase = False
            storage_path = None
    else:
        # Local disk storage
        local_path = UPLOAD_FOLDER / stored_name
        local_path.write_bytes(content)

    # 4. Insert database record
    connection = get_db_connection()
    try:
        connection.execute(
            """
            INSERT INTO documents
                (owner_id, original_name, stored_name, storage_path, sha256_hash, file_size, category)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                safe_name,
                stored_name,
                storage_path,
                file_hash,
                file_size,
                category,
            ),
        )
        connection.commit()

        log_audit(
            action="UPLOAD",
            document_name=safe_name,
            status="SUCCESS",
            details=f"Stored via {'Supabase' if use_supabase else 'Local'}, Category: {category}"
        )

    except Exception as e:
        connection.rollback()
        # Clean up storage object on database failure to avoid orphans
        if use_supabase and storage_path:
            delete_document_from_supabase(storage_path)
        else:
            (UPLOAD_FOLDER / stored_name).unlink(missing_ok=True)
        log_audit(action="UPLOAD_FAILED", document_name=safe_name, status="FAILED", details=str(e))
        logger.error(f"Upload insert failed: {e}")
        return redirect(url_for("documents", error=f"Upload database error: {str(e)[:120]}"))

    finally:
        connection.close()

    return redirect(url_for("documents", message="Document uploaded and cryptographically secured with SHA-256!"))


# ---------------- DOWNLOAD DOCUMENT (AUTHENTICATED & VERIFIED) ----------------

@app.route("/documents/download/<int:document_id>")
@app.route("/download/<int:document_id>")
@login_required
def download_document(document_id):
    current_user_id = get_current_user_id()
    if not current_user_id:
        return redirect(url_for("login"))
    is_admin = session.get("role") == "admin"

    connection = get_db_connection()
    try:
        document = connection.execute(
            "SELECT * FROM documents WHERE id = ?",
            (document_id,),
        ).fetchone()

        if not document:
            log_audit("DOWNLOAD_FAILED", status="DENIED", details=f"Doc ID {document_id} not found")
            return "Document not found or access denied.", 404

        # Authorization check: User must be Document Owner, Admin, or have explicit sharing permission
        is_owner = (document["owner_id"] == current_user_id)
        permission_record = None

        if not is_owner and not is_admin:
            permission_record = connection.execute(
                "SELECT permission FROM document_permissions WHERE document_id = ? AND user_id = ?",
                (document_id, current_user_id),
            ).fetchone()

            if not permission_record:
                log_audit(
                    action="UNAUTHORIZED_DOWNLOAD_ATTEMPT",
                    document_name=document["original_name"],
                    status="DENIED",
                    details=f"User {current_user_id} attempted unauthorized access to document {document_id}"
                )
                return "Access denied: You do not have permission to view or download this document.", 403

        # Read file bytes & verify SHA-256 integrity
        storage_path = document["storage_path"] if "storage_path" in document.keys() else None
        use_supabase = is_storage_configured() and storage_path

        if use_supabase:
            file_bytes = download_document_from_supabase(storage_path)
            if not file_bytes:
                log_audit(
                    action="DOWNLOAD_FAILED",
                    document_name=document["original_name"],
                    status="FAILED",
                    details="File missing in Supabase Storage"
                )
                return "Stored document is missing in Supabase Storage.", 404

            current_hash = hashlib.sha256(file_bytes).hexdigest()
            if current_hash != document["sha256_hash"]:
                log_audit(
                    action="INTEGRITY_CHECK_FAILED",
                    document_name=document["original_name"],
                    status="DENIED",
                    details="SHA-256 hash mismatch between database record and Supabase Storage object"
                )
                return "Integrity check failed! Document may have been modified or corrupted.", 409

            log_audit(
                action="DOWNLOAD",
                document_name=document["original_name"],
                status="SUCCESS",
                details=f"Downloaded via Supabase by {'Owner' if is_owner else 'Viewer'}"
            )

            # Return file content with strict caching headers
            response = send_file(
                BytesIO(file_bytes),
                as_attachment=True,
                download_name=document["original_name"],
                mimetype="application/octet-stream",
            )
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            return response

        else:
            # Local filesystem fallback
            file_path = UPLOAD_FOLDER / document["stored_name"]
            if not file_path.is_file():
                log_audit("DOWNLOAD_FAILED", document["original_name"], status="FAILED", details="Local file missing")
                return "Stored document is missing.", 404

            current_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
            if current_hash != document["sha256_hash"]:
                log_audit(
                    action="INTEGRITY_CHECK_FAILED",
                    document_name=document["original_name"],
                    status="DENIED",
                    details="SHA-256 hash mismatch on local disk"
                )
                return "Integrity check failed! Document may have been modified.", 409

            log_audit(
                action="DOWNLOAD",
                document_name=document["original_name"],
                status="SUCCESS",
                details="Downloaded from local storage"
            )

            response = send_from_directory(
                str(UPLOAD_FOLDER),
                document["stored_name"],
                as_attachment=True,
                download_name=document["original_name"],
            )
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            return response

    finally:
        connection.close()


# ---------------- SHORT-LIVED SIGNED DOWNLOAD URL ----------------

@app.route("/documents/signed-url/<int:document_id>")
@app.route("/signed-url/<int:document_id>")
@login_required
def signed_download_url(document_id):
    """
    Generates a 60-second temporary signed bearer URL for authorized downloads.
    Only called AFTER verifying authentication and ownership/sharing permissions.
    """
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({"error": "Unauthorized"}), 401
    is_admin = session.get("role") == "admin"

    connection = get_db_connection()
    try:
        document = connection.execute(
            "SELECT * FROM documents WHERE id = ?",
            (document_id,),
        ).fetchone()

        if not document:
            return jsonify({"error": "Document not found"}), 404

        is_owner = (document["owner_id"] == current_user_id)
        if not is_owner and not is_admin:
            perm = connection.execute(
                "SELECT permission FROM document_permissions WHERE document_id = ? AND user_id = ?",
                (document_id, current_user_id),
            ).fetchone()
            if not perm:
                log_audit("UNAUTHORIZED_SIGNED_URL_REQUEST", document["original_name"], status="DENIED")
                return jsonify({"error": "Access denied"}), 403

        storage_path = document["storage_path"] if "storage_path" in document.keys() else None
        if not is_storage_configured() or not storage_path:
            # Fallback redirect to direct download
            return redirect(url_for("download_document", document_id=document_id))

        signed_url = create_signed_download_url(storage_path, expires_in_seconds=60)
        if not signed_url:
            return jsonify({"error": "Failed to create signed URL"}), 500

        log_audit(
            action="SIGNED_URL_ISSUED",
            document_name=document["original_name"],
            status="SUCCESS",
            details="Issued 60s temporary signed URL"
        )
        return redirect(signed_url)

    finally:
        connection.close()


# ---------------- SHARING & PERMISSIONS (OWNER CONTROL) ----------------

@app.route("/documents/share/<int:document_id>", methods=["POST"])
@app.route("/share/<int:document_id>", methods=["POST"])
@login_required
def share_document(document_id):
    current_user_id = get_current_user_id()
    if not current_user_id:
        return redirect(url_for("login"))
    target_username = request.form.get("target_username", "").strip()
    permission = request.form.get("permission", "READ").strip().upper()
    if permission not in ("READ", "EDIT"):
        permission = "READ"

    conn = get_db_connection()
    try:
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
        if not doc:
            return "Document not found.", 404

        # Only the owner or an admin can grant permissions
        if doc["owner_id"] != current_user_id and session.get("role") != "admin":
            log_audit(
                action="UNAUTHORIZED_SHARE_ATTEMPT",
                document_name=doc["original_name"],
                status="DENIED",
                details=f"User {current_user_id} tried to share document owned by {doc['owner_id']}"
            )
            return "Access denied: Only document owners can grant permissions.", 403

        target_user = conn.execute(
            "SELECT id, username FROM users WHERE username = ?",
            (target_username,)
        ).fetchone()

        if not target_user:
            return "Target user not found.", 404

        if target_user["id"] == current_user_id:
            return "Cannot share document with yourself.", 400

        # Check existing permission
        existing = conn.execute(
            "SELECT id FROM document_permissions WHERE document_id = ? AND user_id = ?",
            (document_id, target_user["id"])
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE document_permissions SET permission = ?, granted_by = ? WHERE id = ?",
                (permission, current_user_id, existing["id"])
            )
        else:
            conn.execute(
                """
                INSERT INTO document_permissions (document_id, user_id, permission, granted_by)
                VALUES (?, ?, ?, ?)
                """,
                (document_id, target_user["id"], permission, current_user_id)
            )

        conn.commit()
        log_audit(
            action="SHARE",
            document_name=doc["original_name"],
            status="SUCCESS",
            details=f"Granted {permission} access to {target_username}"
        )

    finally:
        conn.close()

    return redirect(url_for("documents"))


@app.route("/documents/revoke/<int:permission_id>", methods=["POST"])
@app.route("/revoke/<int:permission_id>", methods=["POST"])
@login_required
def revoke_permission(permission_id):
    current_user_id = get_current_user_id()
    if not current_user_id:
        return redirect(url_for("login"))

    conn = get_db_connection()
    try:
        perm = conn.execute(
            """
            SELECT p.*, d.owner_id, d.original_name, u.username as recipient
            FROM document_permissions p
            JOIN documents d ON p.document_id = d.id
            JOIN users u ON p.user_id = u.id
            WHERE p.id = ?
            """,
            (permission_id,)
        ).fetchone()

        if not perm:
            return "Permission record not found.", 404

        # Only the owner or an admin can revoke permissions
        if perm["owner_id"] != current_user_id and session.get("role") != "admin":
            log_audit(
                action="UNAUTHORIZED_REVOKE_ATTEMPT",
                document_name=perm["original_name"],
                status="DENIED"
            )
            return "Access denied: Only document owners can revoke permissions.", 403

        conn.execute("DELETE FROM document_permissions WHERE id = ?", (permission_id,))
        conn.commit()

        log_audit(
            action="REVOKE",
            document_name=perm["original_name"],
            status="SUCCESS",
            details=f"Revoked access from {perm['recipient']}"
        )

    finally:
        conn.close()

    return redirect(url_for("documents"))


# ---------------- DOCUMENT DELETION (OWNER ONLY) ----------------

@app.route("/documents/delete/<int:document_id>", methods=["POST"])
@app.route("/delete/<int:document_id>", methods=["POST"])
@login_required
def delete_document(document_id):
    current_user_id = get_current_user_id()
    if not current_user_id:
        return redirect(url_for("login"))

    conn = get_db_connection()
    try:
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
        if not doc:
            return "Document not found.", 404

        # Only the owner or an admin can delete the document
        if doc["owner_id"] != current_user_id and session.get("role") != "admin":
            log_audit(
                action="UNAUTHORIZED_DELETE_ATTEMPT",
                document_name=doc["original_name"],
                status="DENIED",
                details=f"User {current_user_id} attempted to delete doc {document_id}"
            )
            return "Access denied: Only document owners can delete their documents.", 403

        # 1. Remove from Supabase Storage or local disk
        storage_path = doc["storage_path"] if "storage_path" in doc.keys() else None
        if is_storage_configured() and storage_path:
            delete_document_from_supabase(storage_path)
        else:
            (UPLOAD_FOLDER / doc["stored_name"]).unlink(missing_ok=True)

        # 2. Remove document and cascade-delete permissions from database
        conn.execute("DELETE FROM documents WHERE id = ?", (document_id,))
        conn.commit()

        log_audit(action="DELETE", document_name=doc["original_name"], status="SUCCESS")

    finally:
        conn.close()

    return redirect(url_for("documents"))


# ---------------- ADMIN AUDIT LOGS ----------------

@app.route("/admin/audit-logs")
@app.route("/audit-logs")
@app.route("/activity-logs.html")
@admin_required
def audit_logs():
    connection = get_db_connection()
    try:
        logs = connection.execute(
            """
            SELECT audit_logs.*, users.username
            FROM audit_logs
            LEFT JOIN users ON audit_logs.user_id = users.id
            ORDER BY audit_logs.id DESC
            LIMIT 500
            """
        ).fetchall()
    finally:
        connection.close()

    return render_template("audit_logs.html", logs=logs)


# ---------------- ADMIN USERS ----------------

@app.route("/admin/users")
@app.route("/admin-users")
@admin_required
def admin_users():
    connection = get_db_connection()
    try:
        users = connection.execute(
            """
            SELECT id, username, role, created_at
            FROM users
            ORDER BY id DESC
            """
        ).fetchall()
    finally:
        connection.close()

    return render_template("admin_users.html", users=users)


# ---------------- APPLICATION ENTRY POINT ----------------

if __name__ == "__main__":
    # Disable debug in production environments
    debug_mode = os.environ.get("FLASK_ENV") == "development"
    app.run(debug=debug_mode, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))