
"""Shared JWT authentication and role-based authorization.

Used by all Flask services in the security incident system.

The Users service must verify credentials before issuing a token.
Protected routes use require_roles() to authenticate requests.
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import g, jsonify, request

from shared.database import get_db


ROLES = {"ADMIN", "ANALYST", "EMPLOYEE", "AUDITOR"}
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "security-incident-system"
TOKEN_LIFETIME_MINUTES = 60


def _get_jwt_secret():
    """Load the shared JWT signing key from the environment."""
    secret = os.getenv("JWT_SECRET")

    if not secret or len(secret.encode("utf-8")) < 32:
        raise RuntimeError(
            "JWT_SECRET must contain at least 32 bytes "
            "and must be configured in the environment."
        )

    return secret


def create_access_token(user_id):
    """Create a signed JWT after successful user login.

    Args:
        user_id: Database ID of the authenticated user.

    Returns:
        A signed JWT string valid for 60 minutes.

    Note:
        This function does not verify passwords.
        The Users login endpoint must authenticate the user
        and check their account status before calling it.
    """
    if (
        isinstance(user_id, bool)
        or not isinstance(user_id, int)
        or user_id <= 0
    ):
        raise ValueError("A valid user ID is required.")

    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "iss": JWT_ISSUER,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=TOKEN_LIFETIME_MINUTES),
        "type": "access",
    }

    return jwt.encode(
        payload,
        _get_jwt_secret(),
        algorithm=JWT_ALGORITHM,
    )


def current_user():
    """Return the authenticated user for the current request."""
    return getattr(g, "current_user", None)


def _error(message, status_code):
    """Return a consistent JSON authentication error."""
    return jsonify({
        "status": "error",
        "message": message,
    }), status_code


def require_roles(*allowed_roles):
    """Protect a Flask route using JWT authentication and roles.

    Usage:
        @require_roles("ADMIN")
        @require_roles("ADMIN", "ANALYST", "AUDITOR")

    The user's current role and account status are retrieved
    from the shared users table instead of trusting client data.
    """
    if not allowed_roles or not set(allowed_roles).issubset(ROLES):
        raise ValueError("Specify one or more valid roles.")

    def decorator(view_function):

        @wraps(view_function)
        def wrapper(*args, **kwargs):
            authorization = request.headers.get(
                "Authorization", ""
            )

            parts = authorization.split()

            if (
                len(parts) != 2
                or parts[0].lower() != "bearer"
            ):
                return _error(
                    "Bearer authentication is required.",
                    401,
                )

            token = parts[1]

            try:
                payload = jwt.decode(
                    token,
                    _get_jwt_secret(),
                    algorithms=[JWT_ALGORITHM],
                    issuer=JWT_ISSUER,
                    options={
                        "require": [
                            "sub", "iss", "iat", "nbf", "exp"
                        ]
                    },
                )

                if payload.get("type") != "access":
                    raise jwt.InvalidTokenError(
                        "Invalid token type."
                    )

                subject = payload["sub"]

                if (
                    not isinstance(subject, str)
                    or not subject.isdecimal()
                    or int(subject) <= 0
                ):
                    raise jwt.InvalidTokenError(
                        "Invalid token subject."
                    )

                user_id = int(subject)

            except jwt.PyJWTError:
                return _error(
                    "Invalid or expired access token.",
                    401,
                )

            try:
                user_row = get_db().execute(
                    """
                    SELECT id, username, role, account_status
                    FROM users
                    WHERE id = ?
                    """,
                    (user_id,),
                ).fetchone()

            except sqlite3.DatabaseError:
                return _error(
                    "Authentication temporarily unavailable.",
                    503,
                )

            if (
                user_row is None
                or user_row["account_status"] != "Active"
            ):
                return _error(
                    "User account is unavailable or inactive.",
                    401,
                )

            if user_row["role"] not in ROLES:
                return _error(
                    "User role is invalid.",
                    403,
                )

            g.current_user = dict(user_row)

            if user_row["role"] not in allowed_roles:
                return _error(
                    "You do not have permission to perform "
                    "this action.",
                    403,
                )

            return view_function(*args, **kwargs)

        return wrapper

    return decorator
