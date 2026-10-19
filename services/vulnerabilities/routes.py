"""Vulnerability Management API (Service 7) — Sprint 1.

Responsible student: Elias Ghanem.

Routes: POST /vulnerabilities, GET /vulnerabilities,
GET /vulnerabilities/<id>, PUT /vulnerabilities/<id>,
GET /vulnerabilities/search, DELETE /vulnerabilities/<id>.

API authorization:

- ADMIN: all six endpoints.
- ANALYST: list, retrieve, search and update.
- AUDITOR: list, retrieve and search only.
- EMPLOYEE: no access.

Validation rules:

- cve_identifier must look like CVE-YYYY-NNNN (stored in upper case).
- cvss_score must be a number from 0.1 to 10.0 with one decimal place, and
  severity must agree with the CVSS v3.x rating of that score
  (Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0).
- Status always starts as Open and may only advance one stage at a time:
  Open -> Under Investigation -> In Progress -> Resolved -> Closed.
- A CVE may only be tracked once per asset until that record is Closed.

Integration still required: authenticated HTTP audit events and
vulnerability alert notifications.
"""

import math
import re
import sqlite3
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

from shared.auth import require_roles
from shared.database import get_db
from shared.reference_client import use_local_references, lookup_asset
from shared.notification_events import send_critical_security_alert

bp = Blueprint("vulnerabilities", __name__, url_prefix="/vulnerabilities")

SEVERITIES = {"Low", "Medium", "High", "Critical"}
LIFECYCLE = ("Open", "Under Investigation", "In Progress", "Resolved", "Closed")
CREATE_FIELDS = {
    "title", "description", "cve_identifier", "cvss_score", "severity",
    "affected_asset_id", "discovery_source",
}
UPDATE_FIELDS = {"description", "severity", "status", "cvss_score", "resolution_date"}
SEARCH_FIELDS = {"cve_identifier", "severity", "affected_asset_id", "status"}
CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")
VULNERABILITY_COLUMNS = (
    "id", "title", "description", "cve_identifier", "cvss_score", "severity",
    "affected_asset_id", "discovery_source", "status", "created_at",
    "resolution_date",
)
# The asset join only exposes identifying fields, not the full asset record.
SELECT_SQL = (
    "SELECT " + ", ".join(f"v.{column}" for column in VULNERABILITY_COLUMNS) + ", "
    "a.name AS asset_name, a.asset_type AS asset_type, "
    "a.criticality AS asset_criticality "
    "FROM vulnerabilities v LEFT JOIN assets a ON a.id = v.affected_asset_id"
)


class VulnerabilityConflict(Exception):
    """Raised when a request conflicts with the record's current state."""


def _error(message, status_code):
    """Create a consistent JSON error response."""
    return jsonify({"status": "error", "message": message}), status_code


def _json_object():
    """Require a valid JSON object, not an array or malformed JSON."""
    if not request.is_json:
        raise ValueError("Content-Type must be application/json.")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValueError("A valid JSON object is required.")
    return body


def _vulnerability(row):
    """Convert a joined row into the API's vulnerability representation."""
    result = {column: row[column] for column in VULNERABILITY_COLUMNS}
    result["affected_asset"] = None if row["asset_name"] is None else {
        "id": row["affected_asset_id"],
        "name": row["asset_name"],
        "asset_type": row["asset_type"],
        "criticality": row["asset_criticality"],
    }
    return result


def _fetch(db, vulnerability_id):
    """Return one joined vulnerability row, or None."""
    return db.execute(SELECT_SQL + " WHERE v.id = ?", (vulnerability_id,)).fetchone()


def _utc_now():
    """Current UTC time in the same ISO-8601 format as the schema defaults."""
    return _format_timestamp(datetime.now(timezone.utc))


def _format_timestamp(moment):
    """Format an aware datetime as YYYY-MM-DDTHH:MM:SS.mmmZ in UTC."""
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _parse_timestamp(value, field):
    """Parse an ISO-8601 date or date-time; values without a zone are UTC."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an ISO-8601 date or date-time string.")
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        raise ValueError(f"{field} must be an ISO-8601 date or date-time string.") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _required_text(data, field, limit):
    """Return trimmed, nonempty text of at most ``limit`` characters."""
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required and must be nonempty text.")
    value = value.strip()
    if len(value) > limit:
        raise ValueError(f"{field} must be at most {limit} characters.")
    return value


def _cve_identifier(value):
    """Validate and upper-case a CVE identifier such as CVE-2024-3094."""
    if not isinstance(value, str) or not CVE_PATTERN.fullmatch(value.strip().upper()):
        raise ValueError("cve_identifier must have the format CVE-YYYY-NNNN.")
    return value.strip().upper()


def _cvss_score(value):
    """Validate a CVSS base score: 0.1 to 10.0 with one decimal place."""
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("cvss_score must be a number.")
    if not 0.1 <= value <= 10.0:
        raise ValueError("cvss_score must be between 0.1 and 10.0.")
    if round(value, 1) != value:
        raise ValueError("cvss_score must have at most one decimal place.")
    return float(value)


def _severity(value):
    """Validate a severity level."""
    if not isinstance(value, str) or value.strip() not in SEVERITIES:
        raise ValueError("severity must be Low, Medium, High or Critical.")
    return value.strip()


def cvss_severity(score):
    """Map a CVSS v3.x base score to its qualitative severity rating."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _check_severity_matches(severity, score):
    """Reject a severity that disagrees with the CVSS rating of the score."""
    expected = cvss_severity(score)
    if severity != expected:
        raise ValueError(
            f"severity must be {expected} for CVSS score {score} "
            "(CVSS v3.x rating scale)."
        )


def _next_status(status):
    """Return the only status a vulnerability may move to next, or None."""
    if status not in LIFECYCLE or status == LIFECYCLE[-1]:
        return None
    return LIFECYCLE[LIFECYCLE.index(status) + 1]


def validate_new_vulnerability(data):
    """Validate and normalize the body used to create a vulnerability.

    Every field in CREATE_FIELDS is required. Status, timestamps and the
    resolution date are server-managed and cannot be supplied.
    """
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")
    unexpected = set(data) - CREATE_FIELDS
    if unexpected:
        raise ValueError(
            "Unsupported or server-managed field(s): " + ", ".join(sorted(unexpected))
        )
    missing = CREATE_FIELDS - set(data)
    if missing:
        raise ValueError("Missing required field(s): " + ", ".join(sorted(missing)))

    asset_id = data["affected_asset_id"]
    if type(asset_id) is not int or asset_id <= 0:
        raise ValueError("affected_asset_id must be a positive integer.")

    vulnerability = {
        "title": _required_text(data, "title", 200),
        "description": _required_text(data, "description", 5000),
        "cve_identifier": _cve_identifier(data["cve_identifier"]),
        "cvss_score": _cvss_score(data["cvss_score"]),
        "severity": _severity(data["severity"]),
        "affected_asset_id": asset_id,
        "discovery_source": _required_text(data, "discovery_source", 100),
    }
    _check_severity_matches(vulnerability["severity"], vulnerability["cvss_score"])
    return vulnerability


def insert_vulnerability(db, data):
    """Validate, check relationships and insert a vulnerability record."""
    vulnerability = validate_new_vulnerability(data)

    if use_local_references():
        exists = db.execute(
            "SELECT 1 FROM assets WHERE id = ?", (vulnerability["affected_asset_id"],)
        ).fetchone() is not None
    else:
        exists = lookup_asset(vulnerability["affected_asset_id"]) is not None
    if not exists:
        raise ValueError("affected_asset_id does not identify an existing asset.")

    if db.execute(
        """SELECT 1 FROM vulnerabilities
           WHERE cve_identifier = ? AND affected_asset_id = ? AND status != 'Closed'""",
        (vulnerability["cve_identifier"], vulnerability["affected_asset_id"]),
    ).fetchone() is not None:
        raise VulnerabilityConflict(
            "This CVE is already being tracked for this asset."
        )

    columns = list(vulnerability)
    try:
        cursor = db.execute(
            f"INSERT INTO vulnerabilities ({', '.join(columns)}, status) "
            f"VALUES ({', '.join('?' for _ in columns)}, 'Open')",
            [vulnerability[column] for column in columns],
        )
        db.commit()
    except sqlite3.DatabaseError:
        db.rollback()
        raise
    return _vulnerability(_fetch(db, cursor.lastrowid))


def validate_update(data):
    """Validate the format of an update body (business rules come later)."""
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")
    if not data:
        raise ValueError("At least one update field is required.")
    unknown = set(data) - UPDATE_FIELDS
    if unknown:
        raise ValueError(
            "Only description, severity, status, cvss_score and resolution_date "
            "can be updated. Unsupported field(s): " + ", ".join(sorted(unknown))
        )

    changes = {}
    if "description" in data:
        changes["description"] = _required_text(data, "description", 5000)
    if "severity" in data:
        changes["severity"] = _severity(data["severity"])
    if "cvss_score" in data:
        changes["cvss_score"] = _cvss_score(data["cvss_score"])
    if "status" in data:
        status = data["status"]
        if not isinstance(status, str) or status.strip() not in LIFECYCLE:
            raise ValueError("status must be one of: " + ", ".join(LIFECYCLE) + ".")
        changes["status"] = status.strip()
    if "resolution_date" in data:
        resolved_at = _parse_timestamp(data["resolution_date"], "resolution_date")
        if resolved_at > datetime.now(timezone.utc):
            raise ValueError("resolution_date cannot be in the future.")
        changes["resolution_date"] = resolved_at
    return changes


def apply_update_rules(row, changes):
    """Apply lifecycle, severity and resolution rules to validated changes.

    Returns the column values to write. Raises VulnerabilityConflict when
    the change is invalid for the record's current status, and ValueError
    when the resulting severity/CVSS pair or resolution date is invalid.
    """
    current_status = row["status"]
    if current_status == "Closed":
        raise VulnerabilityConflict("Closed vulnerabilities cannot be modified.")

    updates = dict(changes)
    new_status = changes.get("status", current_status)
    if new_status != current_status:
        allowed = _next_status(current_status)
        if new_status != allowed:
            hint = f" The next allowed status is {allowed}." if allowed else ""
            raise VulnerabilityConflict(
                f"Invalid status transition from {current_status} to {new_status}.{hint}"
            )

    if "severity" in changes or "cvss_score" in changes:
        score = changes.get("cvss_score", row["cvss_score"])
        if score is not None:
            _check_severity_matches(changes.get("severity", row["severity"]), score)

    if "resolution_date" in changes:
        if new_status not in ("Resolved", "Closed"):
            raise VulnerabilityConflict(
                "resolution_date can only be set when the vulnerability is "
                "Resolved or Closed."
            )
        resolved_at = changes["resolution_date"]
        created_at = _parse_timestamp(row["created_at"], "created_at")
        if resolved_at.date() < created_at.date():
            raise ValueError("resolution_date cannot be before the creation date.")
        updates["resolution_date"] = _format_timestamp(resolved_at)
    elif new_status == "Resolved" and current_status != "Resolved":
        updates["resolution_date"] = _utc_now()
    return updates


@bp.post("")
@require_roles("ADMIN")
def create_vulnerability():
    """POST /vulnerabilities: register a vulnerability (ADMIN only).

    Author: Elias Ghanem.

    Requires title, description, cve_identifier, cvss_score, severity,
    affected_asset_id and discovery_source. The status always starts as
    Open. Returns 201, 400, 401, 403, 409 or 500.
    """
    try:
        vulnerability = insert_vulnerability(get_db(), _json_object())
    except VulnerabilityConflict as exc:
        return _error(str(exc), 409)
    except ValueError as exc:
        return _error(str(exc), 400)
    except sqlite3.DatabaseError:
        return _error("Unable to create vulnerability.", 500)

    send_critical_security_alert("vulnerabilities", vulnerability["id"], vulnerability["severity"])
    response = jsonify({
        "status": "success",
        "message": "Vulnerability created successfully.",
        "vulnerability": vulnerability,
    })
    response.status_code = 201
    response.headers["Location"] = f"/vulnerabilities/{vulnerability['id']}"
    return response


@bp.get("")
@require_roles("ADMIN", "ANALYST", "AUDITOR")
def list_vulnerabilities():
    """GET /vulnerabilities: list every vulnerability, newest first.

    Author: Elias Ghanem.

    Each record includes its severity, current status and the affected
    asset's identifying details. Returns 200, 401, 403 or 500.
    """
    try:
        rows = get_db().execute(SELECT_SQL + " ORDER BY v.id DESC").fetchall()
    except sqlite3.DatabaseError:
        return _error("Unable to retrieve vulnerabilities.", 500)

    vulnerabilities = [_vulnerability(row) for row in rows]
    return jsonify({
        "status": "success",
        "count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }), 200


@bp.get("/search")
@require_roles("ADMIN", "ANALYST", "AUDITOR")
def search_vulnerabilities():
    """GET /vulnerabilities/search: filter by CVE, severity, asset and status.

    Author: Elias Ghanem.

    Query names: cve_identifier, severity, affected_asset_id, status.
    cve_identifier is a case-insensitive partial match (e.g. CVE-2024);
    the other filters are exact. Multiple filters are combined with AND.
    Returns 200 (possibly with an empty list), 400, 401, 403 or 500.
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
        if name == "cve_identifier":
            if not re.fullmatch(r"[A-Za-z0-9-]{1,30}", value):
                return _error("cve_identifier may only contain letters, digits and hyphens.", 400)
            clauses.append("instr(upper(v.cve_identifier), ?) > 0")
            params.append(value.upper())
        elif name == "severity":
            if value not in SEVERITIES:
                return _error("severity must be Low, Medium, High or Critical.", 400)
            clauses.append("v.severity = ?")
            params.append(value)
        elif name == "status":
            if value not in LIFECYCLE:
                return _error("status must be one of: " + ", ".join(LIFECYCLE) + ".", 400)
            clauses.append("v.status = ?")
            params.append(value)
        elif name == "affected_asset_id":
            if not re.fullmatch(r"[0-9]+", value) or int(value) <= 0:
                return _error("affected_asset_id must be a positive integer.", 400)
            clauses.append("v.affected_asset_id = ?")
            params.append(int(value))

    try:
        rows = get_db().execute(
            SELECT_SQL + " WHERE " + " AND ".join(clauses) + " ORDER BY v.id DESC",
            params,
        ).fetchall()
    except sqlite3.DatabaseError:
        return _error("Unable to search vulnerabilities.", 500)

    vulnerabilities = [_vulnerability(row) for row in rows]
    return jsonify({
        "status": "success",
        "count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }), 200


@bp.get("/<int:vulnerability_id>")
@require_roles("ADMIN", "ANALYST", "AUDITOR")
def get_vulnerability(vulnerability_id):
    """GET /vulnerabilities/<id>: return one complete vulnerability record.

    Author: Elias Ghanem.

    Returns 200, 401, 403, 404 or 500.
    """
    try:
        row = _fetch(get_db(), vulnerability_id)
    except sqlite3.DatabaseError:
        return _error("Unable to retrieve vulnerability.", 500)
    if row is None:
        return _error("Vulnerability not found.", 404)
    return jsonify({"status": "success", "vulnerability": _vulnerability(row)}), 200


@bp.put("/<int:vulnerability_id>")
@require_roles("ADMIN", "ANALYST")
def update_vulnerability(vulnerability_id):
    """PUT /vulnerabilities/<id>: update a vulnerability (ADMIN or ANALYST).

    Author: Elias Ghanem.

    Editable fields: description, severity, status, cvss_score and
    resolution_date. Status may only advance one lifecycle stage, the
    severity must stay consistent with the CVSS score, and moving to
    Resolved records the resolution date automatically unless one is
    supplied. Closed records are read-only.
    Returns 200, 400, 401, 403, 404, 409 or 500.
    """
    db = get_db()
    try:
        changes = validate_update(_json_object())
        row = _fetch(db, vulnerability_id)
        if row is None:
            return _error("Vulnerability not found.", 404)
        old_severity = row["severity"]
        updates = apply_update_rules(row, changes)

        # Every column comes from the fixed UPDATE_FIELDS allowlist.
        assignments = ", ".join(f"{column} = ?" for column in updates)
        db.execute(
            f"UPDATE vulnerabilities SET {assignments} WHERE id = ?",
            [*updates.values(), vulnerability_id],
        )
        db.commit()
        row = _fetch(db, vulnerability_id)
    except VulnerabilityConflict as exc:
        return _error(str(exc), 409)
    except ValueError as exc:
        return _error(str(exc), 400)
    except sqlite3.DatabaseError:
        db.rollback()
        return _error("Unable to update vulnerability.", 500)

    if old_severity != "Critical" and row["severity"] == "Critical":
        send_critical_security_alert("vulnerabilities", vulnerability_id, "Critical")
    return jsonify({
        "status": "success",
        "message": "Vulnerability updated successfully.",
        "vulnerability": _vulnerability(row),
    }), 200


@bp.delete("/<int:vulnerability_id>")
@require_roles("ADMIN")
def delete_vulnerability(vulnerability_id):
    """DELETE /vulnerabilities/<id>: remove a vulnerability (ADMIN only).

    Author: Elias Ghanem.

    Returns 200, 401, 403, 404 or 500.
    """
    db = get_db()
    try:
        cursor = db.execute("DELETE FROM vulnerabilities WHERE id = ?", (vulnerability_id,))
        if cursor.rowcount == 0:
            db.rollback()
            return _error("Vulnerability not found.", 404)
        db.commit()
    except sqlite3.DatabaseError:
        db.rollback()
        return _error("Unable to delete vulnerability.", 500)

    return jsonify({
        "status": "success",
        "message": "Vulnerability deleted successfully.",
        "deleted_id": vulnerability_id,
    }), 200
