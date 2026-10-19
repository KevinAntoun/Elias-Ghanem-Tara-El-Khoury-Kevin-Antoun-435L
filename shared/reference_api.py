"""Read-only domain-owned internal reference endpoints.

These are integration endpoints, not part of the assignment's 54 public APIs.
An authenticated producer can request minimum necessary reference metadata over
HTTP; it cannot write the other service's tables or access user password hashes.
"""

import os
import secrets
import sqlite3
from functools import wraps

from flask import jsonify, request
from shared.database import get_db

REFERENCE_PRODUCERS = frozenset({
    "users", "assets", "incidents", "threats", "audit", "reports",
    "vulnerabilities", "notifications", "playbooks",
})


def _protect(owner):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            service = request.headers.get("X-Service-Name", "").strip().lower()
            parts = request.headers.get("Authorization", "").split()
            expected = os.getenv(f"REFERENCE_TOKEN_{owner.upper()}_{service.upper()}")
            if (service not in REFERENCE_PRODUCERS or len(parts) != 2
                    or parts[0].lower() != "service" or not expected
                    or len(expected) < 32 or not secrets.compare_digest(parts[1], expected)):
                return jsonify({"status": "error", "message": "Invalid reference credentials."}), 401
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def register_reference_routes(app, name):
    """Install only the internal reference routes owned by this service."""
    if name == "users":
        @app.get("/internal/references/users/<int:user_id>")
        @_protect("users")
        def internal_user_reference(user_id):
            row = get_db().execute(
                "SELECT id, role, account_status FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if row is None:
                return jsonify({"status": "error", "message": "Not found."}), 404
            return jsonify({"user": dict(row)}), 200

    elif name == "assets":
        @app.get("/internal/references/assets/<int:asset_id>")
        @_protect("assets")
        def internal_asset_reference(asset_id):
            row = get_db().execute("SELECT id FROM assets WHERE id = ?", (asset_id,)).fetchone()
            if row is None:
                return jsonify({"status": "error", "message": "Not found."}), 404
            return jsonify({"asset": dict(row)}), 200

    elif name == "incidents":
        @app.get("/internal/references/incidents/analyst/<int:analyst_id>/assets")
        @_protect("incidents")
        def internal_analyst_assets(analyst_id):
            rows = get_db().execute(
                """SELECT DISTINCT affected_asset_id FROM incidents
                   WHERE assigned_analyst_id = ? AND affected_asset_id IS NOT NULL""",
                (analyst_id,),
            ).fetchall()
            return jsonify({"asset_ids": [row["affected_asset_id"] for row in rows]}), 200
