"""User and identity management API routes.

Responsible student: Student A (replace with full name).
TODO: implement and document these required endpoints:
    - POST /users/register
    - POST /users/login
    - PUT /users/<id>
    - DELETE /users/<id>
    - GET /users
    - GET /users/<username>
"""



import re
import sqlite3

from flask import Blueprint, jsonify, request
from werkzeug.security import generate_password_hash

from shared.database import get_db


bp = Blueprint("users", __name__, url_prefix="/users")


@bp.post("/register")
def register_user():
    """Register a new employee with a securely hashed password.

    Owner: Tara El Khoury
    Authentication: Public registration
    Success: 201 Created
    """
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "status": "error",
            "message": "A JSON object is required"
        }), 400

    required_fields = [
        "full_name",
        "username",
        "email",
        "password",
        "department"
    ]

    for field in required_fields:
        value = data.get(field)

        if not isinstance(value, str) or not value.strip():
            return jsonify({
                "status": "error",
                "message": f"{field} is required"
            }), 400

    full_name = data["full_name"].strip()
    username = data["username"].strip()
    email = data["email"].strip().lower()
    password = data["password"]
    department = data["department"].strip()

    if not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+", email
    ):
        return jsonify({
            "status": "error",
            "message": "Invalid email format"
        }), 400

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        return jsonify({
            "status": "error",
            "message": "Username must be 3-30 characters "
                       "using letters, numbers or underscores"
        }), 400

    if (len(password) < 8
            or len(password) > 128
            or not re.search(r"[A-Z]", password)
            or not re.search(r"[a-z]", password)
            or not re.search(r"\d", password)):
        return jsonify({
            "status": "error",
            "message": "Password must be 8-128 characters "
                       "and contain uppercase, lowercase "
                       "and numeric characters"
        }), 400

    # Public registration can only create regular employees.
    if "role" in data and data["role"] != "EMPLOYEE":
        return jsonify({
            "status": "error",
            "message": "Cannot assign a privileged role"
        }), 403

    if "account_status" in data:
        return jsonify({
            "status": "error",
            "message": "Account status cannot be assigned "
                       "during public registration"
        }), 400

    password_hash = generate_password_hash(password)

    conn = get_db()

    try:
        cursor = conn.execute(
            """
            INSERT INTO users (
                full_name,
                username,
                email,
                password_hash,
                department,
                role,
                account_status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                full_name,
                username,
                email,
                password_hash,
                department,
                "EMPLOYEE",
                "Active"
            )
        )

        conn.commit()
        user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({
            "status": "error",
            "message": "Username or email already exists"
        }), 409

    except sqlite3.DatabaseError:
        conn.rollback()
        return jsonify({
            "status": "error",
            "message": "Unable to register user"
        }), 500

    return jsonify({
        "status": "success",
        "message": "User registered successfully",
        "user": {
            "id": user_id,
            "full_name": full_name,
            "username": username,
            "email": email,
            "department": department,
            "role": "EMPLOYEE",
            "account_status": "Active"
        }
    }), 201
