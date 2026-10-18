"""Incident Management API (Sprint 1).

Responsible student: Tara El Khoury.

Routes: POST /incidents, GET /incidents, GET /incidents/<id>,
PUT /incidents/<id>/assign, PUT /incidents/<id>/status,
POST /incidents/<id>/notes.

Notifications and audit logging are connected through shared authenticated helpers.
"""

import sqlite3
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

from shared.auth import current_user, require_roles
from shared.database import get_db
from shared.reference_client import use_local_references, lookup_user, lookup_asset
from shared.notification_events import send_notification_event

bp = Blueprint("incidents", __name__, url_prefix="/incidents")

SEVERITIES = {"Low", "Medium", "High", "Critical"}
LIFECYCLE = ("Open", "Under Investigation", "Mitigated", "Resolved", "Closed")
INCIDENT_COLUMNS = (
    "id", "title", "description", "category", "severity", "reporter_id",
    "affected_asset_id", "assigned_analyst_id", "status", "created_at",
    "resolution_date",
)


def _error(message, code):
    return jsonify({"status": "error", "message": message}), code


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _positive_id(value):
    return type(value) is int and value > 0


def _text(value, limit=500):
    return isinstance(value, str) and bool(value.strip()) and len(value.strip()) <= limit


def _incident(conn, incident_id):
    return conn.execute(
        f"SELECT {', '.join(INCIDENT_COLUMNS)} FROM incidents WHERE id = ?",
        (incident_id,),
    ).fetchone()


def _visible(row, actor):
    return (
        actor["role"] in {"ADMIN", "AUDITOR"}
        or (actor["role"] == "ANALYST" and row["assigned_analyst_id"] == actor["id"])
        or (actor["role"] == "EMPLOYEE" and row["reporter_id"] == actor["id"])
    )


def _get_notes(conn, incident_id):
    return [dict(row) for row in conn.execute(
        """SELECT id, incident_id, analyst_id, content, created_at
           FROM investigation_notes WHERE incident_id = ? ORDER BY id""",
        (incident_id,),
    ).fetchall()]


@bp.post("")
@require_roles("ADMIN", "EMPLOYEE")
def create_incident():
    """Report an incident; employees can only report for themselves (201)."""
    data = _body()
    if data is None:
        return _error("A JSON object is required.", 400)
    allowed = {"title", "description", "category", "severity", "reporter_id", "affected_asset_id"}
    if set(data) - allowed:
        return _error("Unknown or noneditable incident fields.", 400)
    for field, limit in (("title", 150), ("description", 5000), ("category", 100)):
        if not _text(data.get(field), limit):
            return _error(f"{field} must be a nonempty string of at most {limit} characters.", 400)
    if data.get("severity") not in SEVERITIES:
        return _error("Invalid severity. Use Low, Medium, High or Critical.", 400)
    asset_id = data.get("affected_asset_id")
    if not _positive_id(asset_id):
        return _error("affected_asset_id must be a positive integer.", 400)
    actor = current_user()
    reporter_id = data.get("reporter_id", actor["id"])
    if not _positive_id(reporter_id):
        return _error("reporter_id must be a positive integer.", 400)
    if actor["role"] != "ADMIN" and reporter_id != actor["id"]:
        return _error("You cannot report incidents on behalf of another user.", 403)

    conn = get_db()
    try:
        if use_local_references():
            asset = conn.execute("SELECT id FROM assets WHERE id = ?", (asset_id,)).fetchone()
            reporter = conn.execute(
                "SELECT id FROM users WHERE id = ? AND account_status = 'Active'", (reporter_id,)
            ).fetchone()
        else:
            asset = lookup_asset(asset_id)
            user = lookup_user(reporter_id)
            reporter = user if user and user.get("account_status") == "Active" else None
        if asset is None:
            return _error("Affected asset does not exist.", 400)
        if reporter is None:
            return _error("Reporter does not exist or is inactive.", 400)
        cursor = conn.execute(
            """INSERT INTO incidents
               (title, description, category, severity, reporter_id, affected_asset_id, status)
               VALUES (?, ?, ?, ?, ?, ?, 'Open')""",
            (data["title"].strip(), data["description"].strip(),
             data["category"].strip(), data["severity"], reporter_id, asset_id),
        )
        conn.commit()
        result = dict(_incident(conn, cursor.lastrowid))
    except sqlite3.IntegrityError:
        conn.rollback()
        return _error("Incident references an invalid record.", 409)
    except sqlite3.DatabaseError:
        conn.rollback()
        return _error("Database unavailable.", 503)
    return jsonify({"status": "success", "incident": result}), 201


@bp.get("")
@require_roles("ADMIN", "AUDITOR")
def list_incidents():
    """List all incidents; available to administrators and auditors (200)."""
    try:
        rows = get_db().execute(
            f"SELECT {', '.join(INCIDENT_COLUMNS)} FROM incidents ORDER BY id DESC"
        ).fetchall()
    except sqlite3.DatabaseError:
        return _error("Database unavailable.", 503)
    return jsonify({"status": "success", "incidents": [dict(row) for row in rows]}), 200


@bp.get("/<int:incident_id>")
@require_roles("ADMIN", "AUDITOR", "ANALYST", "EMPLOYEE")
def get_incident(incident_id):
    """Read an incident, with ownership/assignment restriction and notes (200)."""
    try:
        conn = get_db()
        row = _incident(conn, incident_id)
        if row is None:
            return _error("Incident not found.", 404)
        if not _visible(row, current_user()):
            return _error("You cannot view this incident.", 403)
        result = dict(row)
        result["investigation_notes"] = _get_notes(conn, incident_id)
    except sqlite3.DatabaseError:
        return _error("Database unavailable.", 503)
    return jsonify({"status": "success", "incident": result}), 200


@bp.put("/<int:incident_id>/assign")
@require_roles("ADMIN")
def assign_incident(incident_id):
    """Assign an active analyst to an existing incident (200).

    Calls Notifications over HTTP after a successful changed assignment.
    """
    data = _body()
    if data is None or set(data) != {"assigned_analyst_id"}:
        return _error("Provide only assigned_analyst_id in a JSON object.", 400)
    analyst_id = data["assigned_analyst_id"]
    if not _positive_id(analyst_id):
        return _error("assigned_analyst_id must be a positive integer.", 400)
    conn = get_db()
    try:
        row = _incident(conn, incident_id)
        if row is None:
            return _error("Incident not found.", 404)
        if row["status"] == "Closed":
            return _error("A closed incident cannot be assigned.", 409)
        if use_local_references():
            analyst = conn.execute(
                "SELECT id FROM users WHERE id = ? AND role = 'ANALYST' AND account_status = 'Active'",
                (analyst_id,),
            ).fetchone()
        else:
            user = lookup_user(analyst_id)
            analyst = user if user and user.get("role") == "ANALYST" and user.get("account_status") == "Active" else None
        if analyst is None:
            return _error("Assignee must be an active ANALYST.", 400)
        conn.execute(
            "UPDATE incidents SET assigned_analyst_id = ? WHERE id = ?",
            (analyst_id, incident_id),
        )
        conn.commit()
        result = dict(_incident(conn, incident_id))
        changed_assignment = row["assigned_analyst_id"] != analyst_id
    except sqlite3.DatabaseError:
        conn.rollback()
        return _error("Database unavailable.", 503)
    if changed_assignment:
        send_notification_event(
            "incidents", analyst_id,
            f"Incident #{incident_id} assigned to you",
            f"You have been assigned incident #{incident_id} for investigation.",
            "Incident Assignment", result["severity"],
        )
    return jsonify({"status": "success", "incident": result}), 200


@bp.put("/<int:incident_id>/status")
@require_roles("ADMIN", "ANALYST")
def change_incident_status(incident_id):
    """Move an incident exactly one step forward in its required lifecycle (200)."""
    data = _body()
    if data is None or set(data) != {"status"} or not isinstance(data["status"], str):
        return _error("Provide only the new status in a JSON object.", 400)
    new_status = data["status"]
    if new_status not in LIFECYCLE:
        return _error("Unknown incident status.", 400)
    conn = get_db()
    try:
        row = _incident(conn, incident_id)
        if row is None:
            return _error("Incident not found.", 404)
        actor = current_user()
        if actor["role"] == "ANALYST" and row["assigned_analyst_id"] != actor["id"]:
            return _error("Only the assigned analyst can change this incident.", 403)
        current_index = LIFECYCLE.index(row["status"])
        if current_index + 1 >= len(LIFECYCLE) or LIFECYCLE[current_index + 1] != new_status:
            return _error("Status must advance exactly one stage; closed incidents cannot advance.", 409)
        resolution_date = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            if new_status == "Resolved" else row["resolution_date"]
        )
        conn.execute(
            "UPDATE incidents SET status = ?, resolution_date = ? WHERE id = ?",
            (new_status, resolution_date, incident_id),
        )
        conn.commit()
        result = dict(_incident(conn, incident_id))
    except sqlite3.DatabaseError:
        conn.rollback()
        return _error("Database unavailable.", 503)
    return jsonify({"status": "success", "incident": result}), 200


@bp.post("/<int:incident_id>/notes")
@require_roles("ADMIN", "ANALYST")
def add_investigation_note(incident_id):
    """Append an immutable investigation note as admin or assigned analyst (201)."""
    data = _body()
    if data is None or set(data) != {"content"} or not _text(data.get("content"), 5000):
        return _error("Provide only nonempty content (maximum 5000 characters).", 400)
    actor = current_user()
    conn = get_db()
    try:
        row = _incident(conn, incident_id)
        if row is None:
            return _error("Incident not found.", 404)
        if actor["role"] == "ANALYST" and row["assigned_analyst_id"] != actor["id"]:
            return _error("Only the assigned analyst can add investigation notes.", 403)
        if row["status"] == "Closed":
            return _error("Cannot add investigation notes to a closed incident.", 409)
        cursor = conn.execute(
            "INSERT INTO investigation_notes (incident_id, analyst_id, content) VALUES (?, ?, ?)",
            (incident_id, actor["id"], data["content"].strip()),
        )
        conn.commit()
        note = conn.execute(
            "SELECT id, incident_id, analyst_id, content, created_at FROM investigation_notes WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    except sqlite3.DatabaseError:
        conn.rollback()
        return _error("Database unavailable.", 503)
    return jsonify({"status": "success", "note": dict(note)}), 201
