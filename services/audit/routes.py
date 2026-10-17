"""Service 5 — Security Audit Logging.

Exposes the six required /logs API endpoints.

POST /logs accepts an ADMIN JWT or a separately authenticated internal
service. A service name header alone never authorizes access.
"""

import re
import sqlite3
from datetime import date

from flask import Blueprint, jsonify, request

from shared.auth import current_user, require_roles
from shared.internal_auth import (
    current_internal_service,
    require_admin_or_service,
)
from shared.database import get_db

bp = Blueprint("audit", __name__, url_prefix="/logs")

LOG_SEVERITIES = {"Information", "Warning", "Error", "Critical"}
LOG_FIELDS = "id, user_id, action, description, severity, related_service, created_at"


def _error(message, status_code):
    """Return a consistent JSON error response."""
    return jsonify({"status": "error", "message": message}), status_code


def _json_object():
    """Get a JSON request body or raise ValueError with a safe message."""
    if not request.is_json:
        raise ValueError("Content-Type must be application/json.")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValueError("A valid JSON object is required.")
    return body


def _required_text(data, key, max_length):
    """Return a bounded, non-empty text value."""
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} is required.")
    value = value.strip()
    if len(value) > max_length:
        raise ValueError(f"{key} must be at most {max_length} characters.")
    return value


def validate_log_data(data, *, internal_service=None):
    """Validate an event without trusting caller-provided identity fields.

    A JWT administrator cannot set user_id. A credentialed internal producer
    may attribute a log to a real user, or to NULL for an automated event.
    The producer is not allowed to impersonate a different related_service.
    """
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")

    allowed = {"action", "description", "severity", "related_service"}
    if internal_service is not None:
        allowed.add("user_id")
    unexpected = set(data) - allowed
    if unexpected:
        raise ValueError("Unknown or server-managed fields: " + ", ".join(sorted(unexpected)))

    result = {
        "action": _required_text(data, "action", 100),
        "description": _required_text(data, "description", 1000),
        "severity": _required_text(data, "severity", 20),
    }
    if result["severity"] not in LOG_SEVERITIES:
        raise ValueError("Invalid log severity.")

    if internal_service is None:
        result["related_service"] = _required_text(data, "related_service", 50)
    else:
        claimed_service = data.get("related_service")
        if claimed_service is not None and claimed_service != internal_service:
            raise ValueError("Internal events must match the authenticated service.")
        result["related_service"] = internal_service

    return result


def insert_log(db, data, actor_user_id, *, internal_service=None):
    """Insert a validated event with the authenticated actor/service identity."""
    log = validate_log_data(data, internal_service=internal_service)

    if internal_service is None:
        if type(actor_user_id) is not int or actor_user_id <= 0:
            raise ValueError("Authenticated actor ID is invalid.")
    elif actor_user_id is not None:
        if type(actor_user_id) is not int or actor_user_id <= 0:
            raise ValueError("user_id must be a positive integer or null.")
        if db.execute("SELECT id FROM users WHERE id = ?", (actor_user_id,)).fetchone() is None:
            raise ValueError("user_id does not exist.")

    try:
        cursor = db.execute(
            """INSERT INTO logs
               (user_id, action, description, severity, related_service)
               VALUES (?, ?, ?, ?, ?)""",
            (actor_user_id, log["action"], log["description"],
             log["severity"], log["related_service"]),
        )
        db.commit()
    except sqlite3.DatabaseError:
        db.rollback()
        raise

    row = db.execute(
        f"SELECT {LOG_FIELDS} FROM logs WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return dict(row)


def _positive_int(raw, field):
    """Validate a positive integer supplied as a URL query parameter."""
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9]+", raw):
        raise ValueError(f"{field} must be a positive integer.")
    value = int(raw)
    if value <= 0:
        raise ValueError(f"{field} must be a positive integer.")
    return value


def _iso_date(raw, field):
    """Accept a date in exactly YYYY-MM-DD format."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        raise ValueError(f"{field} must have format YYYY-MM-DD.")
    try:
        parsed = date.fromisoformat(raw)
    except ValueError:
        raise ValueError(f"{field} must be a valid date.") from None
    return parsed.isoformat()


@bp.post("")
@require_admin_or_service
def create_log():
    """POST /logs: create an event as ADMIN or an authenticated service.

    ADMIN: no user_id field; actor is the signed-in administrator.
    Internal service: user_id may identify an actual user or be null; the
    related_service value is forced to the authenticated producer identity.
    Returns 201, 400, 401, 403 or 500 as appropriate.
    """
    try:
        data = _json_object()
        producer = current_internal_service()
        actor_id = data.get("user_id") if producer else current_user()["id"]
        record = insert_log(
            get_db(), data, actor_id, internal_service=producer
        )
    except ValueError as exc:
        return _error(str(exc), 400)
    except sqlite3.DatabaseError:
        return _error("Unable to create audit log.", 500)

    return jsonify({
        "status": "success",
        "message": "Audit log created successfully.",
        "log": record,
    }), 201


@bp.get("")
@require_roles("ADMIN", "AUDITOR")
def list_logs():
    """GET /logs: return all logs in descending ID order (ADMIN/AUDITOR)."""
    try:
        rows = get_db().execute(
            f"SELECT {LOG_FIELDS} FROM logs ORDER BY id DESC"
        ).fetchall()
    except sqlite3.DatabaseError:
        return _error("Unable to retrieve audit logs.", 500)
    logs = [dict(row) for row in rows]
    return jsonify({"status": "success", "count": len(logs), "logs": logs}), 200


@bp.get("/search")
@require_roles("ADMIN", "AUDITOR", "ANALYST")
def search_logs():
    """GET /logs/search: filter by user_id, action, severity, service and dates.

    Optional query parameters: user_id, action, severity, related_service,
    from_date and to_date (YYYY-MM-DD, inclusive). Filters are combined
    using AND, and all SQL values are parameterized.
    """
    allowed = {
        "user_id", "action", "severity", "related_service",
        "from_date", "to_date",
    }
    unknown = set(request.args) - allowed
    if unknown:
        return _error("Unknown search filters: " + ", ".join(sorted(unknown)), 400)

    clauses = []
    values = []
    try:
        if "user_id" in request.args:
            clauses.append("user_id = ?")
            values.append(_positive_int(request.args["user_id"], "user_id"))

        if "action" in request.args:
            action = _required_text(dict(request.args), "action", 100)
            clauses.append("instr(lower(action), lower(?)) > 0")
            values.append(action)

        if "severity" in request.args:
            severity = _required_text(dict(request.args), "severity", 20)
            if severity not in LOG_SEVERITIES:
                raise ValueError("Invalid log severity.")
            clauses.append("severity = ?")
            values.append(severity)

        if "related_service" in request.args:
            service = _required_text(dict(request.args), "related_service", 50)
            clauses.append("related_service = ?")
            values.append(service)

        from_date = (
            _iso_date(request.args["from_date"], "from_date")
            if "from_date" in request.args else None
        )
        to_date = (
            _iso_date(request.args["to_date"], "to_date")
            if "to_date" in request.args else None
        )
        if from_date and to_date and from_date > to_date:
            raise ValueError("from_date must not be after to_date.")
        if from_date:
            clauses.append("date(created_at) >= ?")
            values.append(from_date)
        if to_date:
            clauses.append("date(created_at) <= ?")
            values.append(to_date)

        sql = f"SELECT {LOG_FIELDS} FROM logs"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        rows = get_db().execute(sql, values).fetchall()
    except ValueError as exc:
        return _error(str(exc), 400)
    except sqlite3.DatabaseError:
        return _error("Unable to search audit logs.", 500)

    logs = [dict(row) for row in rows]
    return jsonify({"status": "success", "count": len(logs), "logs": logs}), 200


@bp.get("/user/<int:user_id>")
@require_roles("ADMIN", "AUDITOR")
def get_user_logs(user_id):
    """GET /logs/user/<user_id>: list logs for an actor (ADMIN/AUDITOR).

    Returns HTTP 200 and [] for a user with no matching logs.
    """
    if user_id <= 0:
        return _error("user_id must be a positive integer.", 400)
    try:
        rows = get_db().execute(
            f"SELECT {LOG_FIELDS} FROM logs WHERE user_id = ? ORDER BY id DESC",
            (user_id,),
        ).fetchall()
    except sqlite3.DatabaseError:
        return _error("Unable to retrieve user audit logs.", 500)
    logs = [dict(row) for row in rows]
    return jsonify({
        "status": "success", "user_id": user_id,
        "count": len(logs), "logs": logs,
    }), 200


@bp.get("/<int:log_id>")
@require_roles("ADMIN", "AUDITOR", "ANALYST")
def get_log(log_id):
    """GET /logs/<id>: retrieve one audit record or return 404."""
    try:
        row = get_db().execute(
            f"SELECT {LOG_FIELDS} FROM logs WHERE id = ?", (log_id,)
        ).fetchone()
    except sqlite3.DatabaseError:
        return _error("Unable to retrieve audit log.", 500)
    if row is None:
        return _error("Audit log not found.", 404)
    return jsonify({"status": "success", "log": dict(row)}), 200


@bp.delete("/<int:log_id>")
@require_roles("ADMIN")
def delete_log(log_id):
    """DELETE /logs/<id>: admin delete with an atomic deletion audit trail.

    Uses one SQLite transaction to delete the target and insert a fresh
    AUDIT_LOG_DELETED event documenting the verified administrator's action.
    Historical rows are never updated. Returns HTTP 200 or 404.
    """
    db = get_db()
    try:
        # BEGIN makes both operations atomic. No commit occurs between them.
        db.execute("BEGIN")
        cursor = db.execute("DELETE FROM logs WHERE id = ?", (log_id,))
        if cursor.rowcount == 0:
            db.rollback()
            return _error("Audit log not found.", 404)
        db.execute(
            """INSERT INTO logs
               (user_id, action, description, severity, related_service)
               VALUES (?, ?, ?, ?, ?)""",
            (
                current_user()["id"], "AUDIT_LOG_DELETED",
                f"Administrator deleted audit log ID {log_id}.",
                "Warning", "audit",
            ),
        )
        db.commit()
    except sqlite3.DatabaseError:
        db.rollback()
        return _error("Unable to delete audit log.", 500)
    return jsonify({
        "status": "success",
        "message": "Audit log deleted successfully; deletion recorded.",
        "deleted_id": log_id,
    }), 200
