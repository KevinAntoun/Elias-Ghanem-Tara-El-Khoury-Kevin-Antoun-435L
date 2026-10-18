"""Notification and Alert Management API (Service 8) — Sprint 1.

Responsible student: Elias Ghanem.

Routes: POST /notifications, GET /notifications/user/<user_id>,
GET /notifications/<id>, PUT /notifications/<id>/read,
GET /notifications/search, DELETE /notifications/<id>.

API authorization:

- ADMIN: all six endpoints.
- ANALYST: user history, retrieve, mark as read and search.
- EMPLOYEE: user history, retrieve and mark as read.
- AUDITOR: user history, retrieve and search (read-only).

Ownership rules:

- ANALYST and EMPLOYEE users may only view or mark their own notifications
  (403 otherwise). An analyst's search only returns their own notifications.
- ADMIN and AUDITOR users can see every notification.

Validation rules:

- notification_type must be Incident Assignment, Security Alert,
  System Notification, Threat Alert or Vulnerability Alert.
- severity must be Low, Medium, High or Critical.
- user_id must identify an existing, active user.
- Status always starts as Unread with no read date. Marking a notification
  as read records the read date once; repeating the request keeps it.

Internal creation: valid NOTIFICATION_TOKEN_* credentials for incidents,
threats, and vulnerabilities; ordinary employees still cannot create alerts.
"""

import re
import sqlite3
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

from shared.auth import current_user, require_roles
from shared.internal_auth import require_admin_or_notification_service
from shared.database import get_db
from shared.reference_client import use_local_references, lookup_user

bp = Blueprint("notifications", __name__, url_prefix="/notifications")

NOTIFICATION_TYPES = (
    "Incident Assignment", "Security Alert", "System Notification",
    "Threat Alert", "Vulnerability Alert",
)
SEVERITIES = ("Low", "Medium", "High", "Critical")
STATUSES = ("Unread", "Read")
CREATE_FIELDS = {"user_id", "title", "message", "notification_type", "severity"}
SEARCH_FIELDS = {"user_id", "notification_type", "severity", "status"}
# Roles that may only see notifications addressed to themselves.
OWNER_ONLY_ROLES = {"ANALYST", "EMPLOYEE"}
NOTIFICATION_COLUMNS = (
    "id", "user_id", "title", "message", "notification_type", "severity",
    "status", "created_at", "read_at",
)
SELECT_SQL = "SELECT " + ", ".join(NOTIFICATION_COLUMNS) + " FROM notifications"
NEWEST_FIRST = " ORDER BY created_at DESC, id DESC"


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


def _notification(row):
    """Convert a database row into the API's notification representation."""
    return {column: row[column] for column in NOTIFICATION_COLUMNS}


def _fetch(db, notification_id):
    """Return one notification row, or None."""
    return db.execute(SELECT_SQL + " WHERE id = ?", (notification_id,)).fetchone()


def _utc_now():
    """Current UTC time in the same ISO-8601 format as the schema defaults."""
    moment = datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _owner_only():
    """Return True when the caller may only access their own notifications."""
    return current_user()["role"] in OWNER_ONLY_ROLES


def _may_access(row):
    """Check whether the current user may view or mark this notification."""
    return not _owner_only() or row["user_id"] == current_user()["id"]


def _required_text(data, field, limit):
    """Return trimmed, nonempty text of at most ``limit`` characters."""
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required and must be nonempty text.")
    value = value.strip()
    if len(value) > limit:
        raise ValueError(f"{field} must be at most {limit} characters.")
    return value


def _choice(value, field, allowed):
    """Validate that ``value`` is one of the allowed labels."""
    if not isinstance(value, str) or value.strip() not in allowed:
        raise ValueError(f"{field} must be one of: " + ", ".join(allowed) + ".")
    return value.strip()


def validate_new_notification(data):
    """Validate and normalize the body used to create a notification.

    Every field in CREATE_FIELDS is required. Status, creation date and
    read date are server-managed and cannot be supplied.
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

    user_id = data["user_id"]
    if type(user_id) is not int or user_id <= 0:
        raise ValueError("user_id must be a positive integer.")

    return {
        "user_id": user_id,
        "title": _required_text(data, "title", 200),
        "message": _required_text(data, "message", 5000),
        "notification_type": _choice(
            data["notification_type"], "notification_type", NOTIFICATION_TYPES
        ),
        "severity": _choice(data["severity"], "severity", SEVERITIES),
    }


def insert_notification(db, data):
    """Validate the body, check the recipient and insert an Unread notification."""
    notification = validate_new_notification(data)

    recipient = (db.execute(
        "SELECT account_status FROM users WHERE id = ?", (notification["user_id"],)
    ).fetchone() if use_local_references() else lookup_user(notification["user_id"]))
    if recipient is None or recipient["account_status"] != "Active":
        raise ValueError("user_id does not identify an existing active user.")

    columns = list(notification)
    try:
        cursor = db.execute(
            f"INSERT INTO notifications ({', '.join(columns)}, status, read_at) "
            f"VALUES ({', '.join('?' for _ in columns)}, 'Unread', NULL)",
            [notification[column] for column in columns],
        )
        db.commit()
    except sqlite3.DatabaseError:
        db.rollback()
        raise
    return _notification(_fetch(db, cursor.lastrowid))


@bp.post("")
@require_admin_or_notification_service
def create_notification():
    """POST /notifications: send as ADMIN or trusted notification producer.

    Author: Elias Ghanem.

    Requires user_id, title, message, notification_type and severity.
    The status always starts as Unread and read_at as null.
    Returns 201, 400, 401, 403 or 500.
    """
    try:
        notification = insert_notification(get_db(), _json_object())
    except ValueError as exc:
        return _error(str(exc), 400)
    except sqlite3.DatabaseError:
        return _error("Unable to create notification.", 500)

    response = jsonify({
        "status": "success",
        "message": "Notification created successfully.",
        "notification": notification,
    })
    response.status_code = 201
    response.headers["Location"] = f"/notifications/{notification['id']}"
    return response


@bp.get("/user/<int:user_id>")
@require_roles("ADMIN", "ANALYST", "EMPLOYEE", "AUDITOR")
def list_user_notifications(user_id):
    """GET /notifications/user/<user_id>: a user's notification history.

    Author: Elias Ghanem.

    Returns every notification for the user, newest first. Analysts and
    employees may only request their own history. An existing user with no
    notifications gets an empty list. Returns 200, 401, 403, 404 or 500.
    """
    if _owner_only() and user_id != current_user()["id"]:
        return _error("You can only view your own notifications.", 403)

    db = get_db()
    try:
        exists = (db.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone()
                  if use_local_references() else lookup_user(user_id))
        if exists is None:
            return _error("User not found.", 404)
        rows = db.execute(
            SELECT_SQL + " WHERE user_id = ?" + NEWEST_FIRST, (user_id,)
        ).fetchall()
    except sqlite3.DatabaseError:
        return _error("Unable to retrieve notifications.", 500)

    notifications = [_notification(row) for row in rows]
    return jsonify({
        "status": "success",
        "user_id": user_id,
        "count": len(notifications),
        "notifications": notifications,
    }), 200


@bp.get("/search")
@require_roles("ADMIN", "ANALYST", "AUDITOR")
def search_notifications():
    """GET /notifications/search: filter by user, type, severity and status.

    Author: Elias Ghanem.

    Query names: user_id, notification_type, severity, status. All filters
    are exact matches combined with AND, and at least one is required.
    Analysts only see their own notifications. Returns 200 (possibly with an
    empty list), 400, 401, 403 or 500.
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
        if name == "user_id":
            if not re.fullmatch(r"[0-9]+", value) or int(value) <= 0:
                return _error("user_id must be a positive integer.", 400)
            if _owner_only() and int(value) != current_user()["id"]:
                return _error("You can only search your own notifications.", 403)
            clauses.append("user_id = ?")
            params.append(int(value))
        elif name == "notification_type":
            if value not in NOTIFICATION_TYPES:
                return _error(
                    "notification_type must be one of: " + ", ".join(NOTIFICATION_TYPES) + ".",
                    400,
                )
            clauses.append("notification_type = ?")
            params.append(value)
        elif name == "severity":
            if value not in SEVERITIES:
                return _error("severity must be one of: " + ", ".join(SEVERITIES) + ".", 400)
            clauses.append("severity = ?")
            params.append(value)
        elif name == "status":
            if value not in STATUSES:
                return _error("status must be one of: " + ", ".join(STATUSES) + ".", 400)
            clauses.append("status = ?")
            params.append(value)

    if _owner_only() and "user_id" not in supplied:
        clauses.append("user_id = ?")
        params.append(current_user()["id"])

    try:
        rows = get_db().execute(
            SELECT_SQL + " WHERE " + " AND ".join(clauses) + NEWEST_FIRST, params
        ).fetchall()
    except sqlite3.DatabaseError:
        return _error("Unable to search notifications.", 500)

    notifications = [_notification(row) for row in rows]
    return jsonify({
        "status": "success",
        "count": len(notifications),
        "notifications": notifications,
    }), 200


@bp.get("/<int:notification_id>")
@require_roles("ADMIN", "ANALYST", "EMPLOYEE", "AUDITOR")
def get_notification(notification_id):
    """GET /notifications/<id>: return one notification's details.

    Author: Elias Ghanem.

    Analysts and employees may only view their own notifications.
    Returns 200, 401, 403, 404 or 500.
    """
    try:
        row = _fetch(get_db(), notification_id)
    except sqlite3.DatabaseError:
        return _error("Unable to retrieve notification.", 500)
    if row is None:
        return _error("Notification not found.", 404)
    if not _may_access(row):
        return _error("You can only view your own notifications.", 403)
    return jsonify({"status": "success", "notification": _notification(row)}), 200


@bp.put("/<int:notification_id>/read")
@require_roles("ADMIN", "ANALYST", "EMPLOYEE")
def mark_notification_read(notification_id):
    """PUT /notifications/<id>/read: mark a notification as read.

    Author: Elias Ghanem.

    Sets the status to Read and records the read date. The request is
    idempotent: marking an already-read notification returns 200 and keeps
    the original read date. Analysts and employees may only mark their own
    notifications. No request body is needed.
    Returns 200, 401, 403, 404 or 500.
    """
    db = get_db()
    try:
        row = _fetch(db, notification_id)
        if row is None:
            return _error("Notification not found.", 404)
        if not _may_access(row):
            return _error("You can only mark your own notifications as read.", 403)

        already_read = row["status"] == "Read"
        if not already_read:
            db.execute(
                "UPDATE notifications SET status = 'Read', read_at = ? "
                "WHERE id = ? AND status = 'Unread'",
                (_utc_now(), notification_id),
            )
            db.commit()
            row = _fetch(db, notification_id)
    except sqlite3.DatabaseError:
        db.rollback()
        return _error("Unable to update notification.", 500)

    return jsonify({
        "status": "success",
        "message": (
            "Notification was already marked as read." if already_read
            else "Notification marked as read."
        ),
        "notification": _notification(row),
    }), 200


@bp.delete("/<int:notification_id>")
@require_roles("ADMIN")
def delete_notification(notification_id):
    """DELETE /notifications/<id>: remove a notification (ADMIN only).

    Author: Elias Ghanem.

    Returns 200, 401, 403, 404 or 500.
    """
    db = get_db()
    try:
        cursor = db.execute("DELETE FROM notifications WHERE id = ?", (notification_id,))
        if cursor.rowcount == 0:
            db.rollback()
            return _error("Notification not found.", 404)
        db.commit()
    except sqlite3.DatabaseError:
        db.rollback()
        return _error("Unable to delete notification.", 500)

    return jsonify({
        "status": "success",
        "message": "Notification deleted successfully.",
        "deleted_id": notification_id,
    }), 200
