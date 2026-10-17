"""Threat Intelligence service: create, list, retrieve, search, update and delete.

API authorization:
- ADMIN: all six endpoints.
- ANALYST and AUDITOR: list, retrieve and search only.
- EMPLOYEE: no access.

The shared authentication contract is provided by ``shared.auth.require_roles``.
Audit event delivery must be integrated once the team's Audit service contract
is agreed; this module does not claim to write audit events.
"""

import ipaddress
import re
import sqlite3

from flask import Blueprint, jsonify, request

from shared.auth import require_roles
from shared.database import get_db


bp = Blueprint("threats", __name__, url_prefix="/threats")

THREAT_TYPES = {
    "IP Address",
    "Domain",
    "File Hash",
    "Malware Signature",
    "Other indicators",
}
SEVERITIES = {"Low", "Medium", "High", "Critical"}
CREATE_FIELDS = {"threat_type", "threat_value", "description", "severity", "source"}
UPDATE_FIELDS = {"description", "severity", "source"}
SEARCH_FIELDS = {"threat_type", "threat_value", "severity", "source"}


class DuplicateThreatError(ValueError):
    """Raised when a threat of the same type and normalized value exists."""


def _error(message, status_code):
    """Create a consistent JSON error response."""
    return jsonify({"status": "error", "message": message}), status_code


def _json_body():
    """Require a valid JSON object, not an array or malformed JSON."""
    if not request.is_json:
        raise ValueError("Content-Type must be application/json.")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValueError("A valid JSON object is required.")
    return body


def _optional_text(data, field):
    """Return trimmed optional text; None or whitespace clears a value."""
    value = data.get(field)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{field} must be text or null.")
    return value.strip() or None if value is not None else None


def validate_new_threat(data):
    """Validate and normalize the data used to create a threat.

    IP addresses use Python's ipaddress parser, domains use DNS-label syntax,
    and file hashes permit hexadecimal MD5, SHA-1 or SHA-256 values.
    """
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")

    unexpected = set(data) - CREATE_FIELDS
    if unexpected:
        raise ValueError("Unsupported field(s): " + ", ".join(sorted(unexpected)))

    for field in ("threat_type", "threat_value", "severity"):
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} is required.")

    threat_type = data["threat_type"].strip()
    threat_value = data["threat_value"].strip()
    severity = data["severity"].strip()

    if threat_type not in THREAT_TYPES:
        raise ValueError("Invalid threat type.")
    if severity not in SEVERITIES:
        raise ValueError("Invalid severity.")

    if threat_type == "IP Address":
        try:
            threat_value = str(ipaddress.ip_address(threat_value))
        except ValueError:
            raise ValueError("Invalid IP address.") from None

    elif threat_type == "Domain":
        threat_value = threat_value.lower()
        labels = threat_value.split(".")
        label_pattern = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if (
            len(threat_value) > 253
            or len(labels) < 2
            or not all(re.fullmatch(label_pattern, label) for label in labels)
        ):
            raise ValueError("Invalid domain.")

    elif threat_type == "File Hash":
        if len(threat_value) not in (32, 40, 64) or not re.fullmatch(
            r"[0-9a-fA-F]+", threat_value
        ):
            raise ValueError("Invalid file hash (expected MD5, SHA-1 or SHA-256).")
        threat_value = threat_value.lower()

    return {
        "threat_type": threat_type,
        "threat_value": threat_value,
        "description": _optional_text(data, "description"),
        "severity": severity,
        "source": _optional_text(data, "source"),
    }


def insert_threat(db, data):
    """Insert a validated threat and return the saved record as a dict."""
    threat = validate_new_threat(data)
    try:
        cursor = db.execute(
            """
            INSERT INTO threats
                (threat_type, threat_value, description, severity, source)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                threat["threat_type"],
                threat["threat_value"],
                threat["description"],
                threat["severity"],
                threat["source"],
            ),
        )
        db.commit()
    except sqlite3.IntegrityError as exc:
        db.rollback()
        if "UNIQUE constraint failed: threats.threat_type, threats.threat_value" in str(exc):
            raise DuplicateThreatError("Threat indicator already exists.") from exc
        raise

    row = db.execute("SELECT * FROM threats WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return dict(row)


def _escape_like(value):
    """Escape SQL LIKE wildcard characters in a literal search term."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@bp.post("")
@require_roles("ADMIN")
def create_threat():
    """POST /threats: create a threat (ADMIN only).

    Expects threat_type, threat_value and severity; description and source
    are optional. Returns 201, 400, 401, 403, 409 or 500.
    """
    try:
        data = _json_body()
        threat = insert_threat(get_db(), data)
    except DuplicateThreatError as exc:
        return _error(str(exc), 409)
    except ValueError as exc:
        return _error(str(exc), 400)
    except sqlite3.DatabaseError:
        return _error("Unable to create threat.", 500)

    response = jsonify({
        "status": "success",
        "message": "Threat created successfully.",
        "threat": threat,
    })
    response.status_code = 201
    response.headers["Location"] = f"/threats/{threat['id']}"
    return response


@bp.get("")
@require_roles("ADMIN", "ANALYST", "AUDITOR")
def list_threats():
    """GET /threats: list all indicators newest first (read-only roles)."""
    try:
        rows = get_db().execute(
            """
            SELECT id, threat_type, threat_value, description,
                   severity, source, created_at
            FROM threats
            ORDER BY id DESC
            """
        ).fetchall()
    except sqlite3.DatabaseError:
        return _error("Unable to retrieve threats.", 500)

    threats = [dict(row) for row in rows]
    return jsonify({"status": "success", "count": len(threats), "threats": threats}), 200


@bp.get("/search")
@require_roles("ADMIN", "ANALYST", "AUDITOR")
def search_threats():
    """GET /threats/search: filter by type, value, severity and/or source.

    Query names: threat_type, threat_value, severity, source.
    Type/severity use exact matches. Value/source use case-insensitive
    substring matches. Multiple filters are combined with AND.
    """
    supplied = request.args.to_dict(flat=False)
    if not supplied:
        return _error("At least one search filter is required.", 400)

    unknown = set(supplied) - SEARCH_FIELDS
    if unknown:
        return _error("Unsupported filter(s): " + ", ".join(sorted(unknown)), 400)

    clauses = []
    params = []
    for name, values in supplied.items():
        if len(values) != 1 or not values[0].strip():
            return _error(f"{name} must be provided exactly once and not be empty.", 400)
        value = values[0].strip()
        if name == "threat_type":
            if value not in THREAT_TYPES:
                return _error("Invalid threat type.", 400)
            clauses.append("threat_type = ?")
            params.append(value)
        elif name == "severity":
            if value not in SEVERITIES:
                return _error("Invalid severity.", 400)
            clauses.append("severity = ?")
            params.append(value)
        elif name in ("threat_value", "source"):
            # name comes only from the fixed SEARCH_FIELDS allowlist.
            clauses.append(f"LOWER({name}) LIKE ? ESCAPE '\\'")
            params.append("%" + _escape_like(value.lower()) + "%")

    sql = (
        "SELECT id, threat_type, threat_value, description, severity, source, created_at "
        "FROM threats WHERE " + " AND ".join(clauses) + " ORDER BY id DESC"
    )
    try:
        rows = get_db().execute(sql, params).fetchall()
    except sqlite3.DatabaseError:
        return _error("Unable to search threats.", 500)

    threats = [dict(row) for row in rows]
    return jsonify({"status": "success", "count": len(threats), "threats": threats}), 200


@bp.get("/<int:threat_id>")
@require_roles("ADMIN", "ANALYST", "AUDITOR")
def get_threat(threat_id):
    """GET /threats/<id>: retrieve one indicator, or return 404."""
    try:
        row = get_db().execute(
            """
            SELECT id, threat_type, threat_value, description,
                   severity, source, created_at
            FROM threats WHERE id = ?
            """,
            (threat_id,),
        ).fetchone()
    except sqlite3.DatabaseError:
        return _error("Unable to retrieve threat.", 500)

    if row is None:
        return _error("Threat not found.", 404)
    return jsonify({"status": "success", "threat": dict(row)}), 200


@bp.put("/<int:threat_id>")
@require_roles("ADMIN")
def update_threat(threat_id):
    """PUT /threats/<id>: edit description, severity and/or source (ADMIN).

    Type/value/ID cannot be changed by this endpoint.
    Returns 200, 400, 401, 403, 404 or 500.
    """
    try:
        data = _json_body()
        if not data:
            raise ValueError("At least one update field is required.")
        unknown = set(data) - UPDATE_FIELDS
        if unknown:
            raise ValueError("Unsupported field(s): " + ", ".join(sorted(unknown)))

        updated = {}
        for name in data:
            if name == "severity":
                severity = data["severity"]
                if not isinstance(severity, str) or severity.strip() not in SEVERITIES:
                    raise ValueError("Invalid severity.")
                updated["severity"] = severity.strip()
            else:
                updated[name] = _optional_text(data, name)

        # Every column is from the fixed UPDATE_FIELDS allowlist.
        assignments = ", ".join(f"{column} = ?" for column in updated)
        params = list(updated.values()) + [threat_id]
        db = get_db()
        cursor = db.execute(
            f"UPDATE threats SET {assignments} WHERE id = ?",
            params,
        )
        if cursor.rowcount == 0:
            db.rollback()
            return _error("Threat not found.", 404)
        db.commit()
        row = db.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()

    except ValueError as exc:
        return _error(str(exc), 400)
    except sqlite3.DatabaseError:
        get_db().rollback()
        return _error("Unable to update threat.", 500)

    return jsonify({
        "status": "success",
        "message": "Threat updated successfully.",
        "threat": dict(row),
    }), 200


@bp.delete("/<int:threat_id>")
@require_roles("ADMIN")
def delete_threat(threat_id):
    """DELETE /threats/<id>: remove an indicator (ADMIN only)."""
    db = get_db()
    try:
        cursor = db.execute("DELETE FROM threats WHERE id = ?", (threat_id,))
        if cursor.rowcount == 0:
            db.rollback()
            return _error("Threat not found.", 404)
        db.commit()
    except sqlite3.DatabaseError:
        db.rollback()
        return _error("Unable to delete threat.", 500)

    return jsonify({
        "status": "success",
        "message": "Threat deleted successfully.",
        "deleted_id": threat_id,
    }), 200
