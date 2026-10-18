"""User and identity management API routes.

Responsible student: Tara El Khoury.

Authentication is shared through ``shared.auth`` and JWTs.
"""

import re
import sqlite3

from flask import Blueprint, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from shared.auth import ROLES, create_access_token, current_user, require_roles
from shared.database import get_db
from dotenv import load_dotenv

load_dotenv()

bp = Blueprint("users", __name__, url_prefix="/users")

_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,30}$")
_ALLOWED_PROFILE_FIELDS = {"full_name", "email", "department"}
_PUBLIC_USER_FIELDS = (
    "id", "full_name", "username", "email", "department",
    "role", "account_status", "created_at", "last_login_at"
)


def _error(message, status_code):
    return jsonify({"status": "error", "message": message}), status_code


def _json_object():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _safe_user(row):
    return {field: row[field] for field in _PUBLIC_USER_FIELDS}


def _valid_email(value):
    return isinstance(value, str) and bool(_EMAIL_PATTERN.fullmatch(value))


def _valid_password(password):
    return (
        isinstance(password, str)
        and 8 <= len(password) <= 128
        and bool(re.search(r"[A-Z]", password))
        and bool(re.search(r"[a-z]", password))
        and bool(re.search(r"\d", password))
    )


@bp.post("/register")
def register_user():
    """Register a regular employee with a securely hashed password (201)."""
    data = _json_object()
    if data is None:
        return _error("A JSON object is required.", 400)

    required = ("full_name", "username", "email", "password", "department")
    if any(not isinstance(data.get(key), str) or not data[key].strip()
           for key in required):
        return _error("full_name, username, email, password and department are required.", 400)

    # Never accept privileges or account state from a public registration request.
    if "role" in data and data["role"] != "EMPLOYEE":
        return _error("Public registration cannot assign elevated roles.", 403)
    if "account_status" in data:
        return _error("Public registration cannot set account_status.", 400)

    full_name = data["full_name"].strip()
    username = data["username"].strip()
    email = data["email"].strip().lower()
    department = data["department"].strip()
    password = data["password"]

    if not _USERNAME_PATTERN.fullmatch(username):
        return _error("Username must be 3-30 letters, digits or underscores.", 400)
    if not _valid_email(email):
        return _error("Invalid email address.", 400)
    if not _valid_password(password):
        return _error("Password must be 8-128 characters with uppercase, lowercase and a digit.", 400)
    if len(full_name) > 150 or len(department) > 100 or len(email) > 254:
        return _error("One or more fields are too long.", 400)

    conn = get_db()
    try:
        cursor = conn.execute(
            """INSERT INTO users
               (full_name, username, email, password_hash, department, role, account_status)
               VALUES (?, ?, ?, ?, ?, 'EMPLOYEE', 'Active')""",
            (full_name, username, email, generate_password_hash(password), department),
        )
        user_id = cursor.lastrowid
        conn.commit()
        user = conn.execute(
            f"SELECT {', '.join(_PUBLIC_USER_FIELDS)} FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    except sqlite3.IntegrityError:
        conn.rollback()
        return _error("Username or email already exists.", 409)
    except sqlite3.DatabaseError:
        conn.rollback()
        return _error("Database unavailable.", 503)

    return jsonify({"status": "success", "message": "User registered.", "user": _safe_user(user)}), 201


@bp.post("/login")
def login_user():
    """Verify credentials and issue a shared JWT for active users (200)."""
    data = _json_object()
    if data is None:
        return _error("A JSON object is required.", 400)
    identifier = data.get("username", data.get("email"))
    password = data.get("password")
    if not isinstance(identifier, str) or not identifier.strip() or not isinstance(password, str) or not password:
        return _error("Username (or email) and password are required.", 400)

    identifier = identifier.strip()
    try:
        conn = get_db()
        user = conn.execute(
            """SELECT id, username, email, password_hash, role, account_status
               FROM users WHERE username = ? OR email = ?""",
            (identifier, identifier.lower()),
        ).fetchone()
    except sqlite3.DatabaseError:
        return _error("Database unavailable.", 503)

    # Same response for unknown users and wrong passwords.
    if user is None or not check_password_hash(user["password_hash"], password):
        return _error("Invalid credentials.", 401)
    if user["account_status"] != "Active":
        return _error("Account is not active.", 403)
    if user["role"] not in {"ADMIN", "ANALYST", "EMPLOYEE", "AUDITOR"}:
        return _error("Account role is invalid.", 403)

    try:
        token = create_access_token(user["id"])
    except RuntimeError:
        return _error("JWT signing is not configured.", 503)

    try:
        conn.execute(
            """UPDATE users
               SET last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
               WHERE id = ?""",
            (user["id"],),
        )
        conn.commit()
    except sqlite3.DatabaseError:
        conn.rollback()
        return _error("Database unavailable.", 503)

    return jsonify({
        "status": "success", "message": "Login successful.",
        "access_token": token, "token_type": "Bearer", "expires_in": 3600,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
    }), 200


@bp.get("")
@require_roles("ADMIN", "AUDITOR")
def list_users():
    """List safe profile fields for administrators and auditors (200)."""
    try:
        rows = get_db().execute(
            f"SELECT {', '.join(_PUBLIC_USER_FIELDS)} FROM users ORDER BY id"
        ).fetchall()
    except sqlite3.DatabaseError:
        return _error("Database unavailable.", 503)
    return jsonify({"status": "success", "users": [_safe_user(row) for row in rows]}), 200


@bp.get("/<string:username>")
@require_roles("ADMIN", "AUDITOR", "ANALYST", "EMPLOYEE")
def get_user(username):
    """Read a profile, restricted to self for employees and analysts (200)."""
    actor = current_user()
    if actor["role"] in {"EMPLOYEE", "ANALYST"} and actor["username"] != username:
        return _error("You may only view your own profile.", 403)
    try:
        row = get_db().execute(
            f"SELECT {', '.join(_PUBLIC_USER_FIELDS)} FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    except sqlite3.DatabaseError:
        return _error("Database unavailable.", 503)
    if row is None:
        return _error("User not found.", 404)
    return jsonify({"status": "success", "user": _safe_user(row)}), 200


@bp.put("/<int:user_id>")
@require_roles("ADMIN", "ANALYST", "EMPLOYEE", "AUDITOR")
def update_user(user_id):
    """Update editable profile fields as admin or the account owner (200)."""
    actor = current_user()
    if actor["role"] != "ADMIN" and actor["id"] != user_id:
        return _error("You may only update your own profile.", 403)
    if actor["role"] == "AUDITOR":
        return _error("Auditors cannot modify user profiles.", 403)

    data = _json_object()
    if data is None:
        return _error("A JSON object is required.", 400)
    if not data:
        return _error("Provide at least one editable profile field.", 400)
    # Roles and account state can be changed only by an authenticated ADMIN.
    admin_fields = {"role", "account_status"} if actor["role"] == "ADMIN" else set()
    allowed = _ALLOWED_PROFILE_FIELDS | admin_fields
    if set(data) - allowed:
        return _error("Fields are not editable by this account.", 400)
    if "role" in data and (not isinstance(data["role"], str) or data["role"] not in ROLES):
        return _error("Invalid role.", 400)
    if "account_status" in data and (not isinstance(data["account_status"], str) or data["account_status"] not in {"Active", "Inactive", "Suspended"}):
        return _error("Invalid account_status.", 400)

    updates = {}
    for field, value in data.items():
        if not isinstance(value, str) or not value.strip():
            return _error(f"{field} must be a nonempty string.", 400)
        updates[field] = value.strip().lower() if field == "email" else value.strip()
    if "email" in updates and (not _valid_email(updates["email"]) or len(updates["email"]) > 254):
        return _error("Invalid email address.", 400)
    if len(updates.get("full_name", "")) > 150 or len(updates.get("department", "")) > 100:
        return _error("One or more fields are too long.", 400)

    conn = get_db()
    try:
        # Lock first so concurrent requests cannot demote the last active admin.
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT id, role, account_status FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if existing is None:
            conn.rollback()
            return _error("User not found.", 404)
        losing_admin = (existing["role"] == "ADMIN" and existing["account_status"] == "Active"
                        and (updates.get("role", existing["role"]) != "ADMIN"
                             or updates.get("account_status", existing["account_status"]) != "Active"))
        if losing_admin:
            remaining = conn.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'ADMIN' AND account_status = 'Active'"
            ).fetchone()[0]
            if remaining <= 1:
                conn.rollback()
                return _error("Cannot deactivate or demote the last active administrator.", 409)
        # Column identifiers come exclusively from a fixed server-side allowlist.
        clause = ", ".join(f"{field} = ?" for field in updates)
        conn.execute(f"UPDATE users SET {clause} WHERE id = ?", (*updates.values(), user_id))
        conn.commit()
        row = conn.execute(
            f"SELECT {', '.join(_PUBLIC_USER_FIELDS)} FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    except sqlite3.IntegrityError:
        conn.rollback()
        return _error("Email already exists.", 409)
    except sqlite3.DatabaseError:
        conn.rollback()
        return _error("Database unavailable.", 503)
    if "role" in updates and updates["role"] != existing["role"]:
        g.audit_action_override = ("ROLE_CHANGED", "Warning")
        g.audit_description_override = f"Administrator changed user #{user_id} role from {existing['role']} to {updates['role']}."
    elif "account_status" in updates and updates["account_status"] != existing["account_status"]:
        g.audit_action_override = ("ACCOUNT_STATUS_CHANGED", "Warning")
        g.audit_description_override = f"Administrator changed user #{user_id} account status."
    return jsonify({"status": "success", "message": "User updated.", "user": _safe_user(row)}), 200


@bp.delete("/<int:user_id>")
@require_roles("ADMIN")
def delete_user(user_id):
    """Delete an account as an administrator; reject linked accounts (200)."""
    actor = current_user()
    if actor["id"] == user_id:
        return _error("Administrators cannot delete their own account.", 403)

    conn = get_db()
    try:
        exists = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if exists is None:
            return _error("User not found.", 404)
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        return _error("Cannot delete a user referenced by other records.", 409)
    except sqlite3.DatabaseError:
        conn.rollback()
        return _error("Database unavailable.", 503)
    return jsonify({"status": "success", "message": "User deleted."}), 200
