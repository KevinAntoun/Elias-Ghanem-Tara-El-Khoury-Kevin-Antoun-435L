"""Security Playbook and Response Automation API (Service 9) — Sprint 1.

Responsible student: Elias Ghanem.

Routes: POST /playbooks, GET /playbooks, GET /playbooks/<id>,
POST /playbooks/<id>/actions, PUT /actions/<id>/status,
DELETE /playbooks/<id>.

API authorization:

- ADMIN: all six endpoints.
- ANALYST: list and retrieve playbooks, add response actions and update
  action status.
- AUDITOR: list and retrieve playbooks only.
- EMPLOYEE: no access.

Validation rules:

- A playbook needs a name (unique, case-insensitive), description,
  incident category and severity (Low, Medium, High or Critical). The
  creator and creation date are recorded by the server.
- Response actions need a description and a positive step number that is
  unique within the playbook. A new step cannot be inserted before a step
  that has already started.
- Action status always starts as Pending and may only advance one stage at
  a time: Pending -> In Progress -> Completed.
- An action may only start or complete once every lower-numbered action in
  its playbook is Completed, so steps are executed in order.
- Completing an action records its completion date. Completed actions are
  read-only, which preserves the execution history.
- Assigned users must be active ADMIN or ANALYST accounts.

Integration still required: authenticated HTTP audit events and
notifications for action assignment and completion.
"""

import sqlite3
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

from shared.auth import current_user, require_roles
from shared.database import get_db
from shared.reference_client import use_local_references, lookup_user

bp = Blueprint("playbooks", __name__, url_prefix="/playbooks")

# The required PUT /actions/<id>/status is outside /playbooks.
actions_bp = Blueprint("actions", __name__, url_prefix="/actions")

SEVERITIES = {"Low", "Medium", "High", "Critical"}
ACTION_LIFECYCLE = ("Pending", "In Progress", "Completed")
ASSIGNABLE_ROLES = ("ADMIN", "ANALYST")
PLAYBOOK_FIELDS = {"name", "description", "incident_category", "severity"}
CREATE_FIELDS = PLAYBOOK_FIELDS | {"actions"}
ACTION_FIELDS = {"description", "step_number", "assigned_user_id"}
STATUS_UPDATE_FIELDS = {"status", "assigned_user_id", "completion_date"}
PLAYBOOK_SELECT_SQL = (
    "SELECT p.id, p.name, p.description, p.incident_category, p.severity, "
    "p.created_by, p.created_at, u.username AS created_by_username, "
    "(SELECT COUNT(*) FROM response_actions r WHERE r.playbook_id = p.id) "
    "AS action_count, "
    "(SELECT COUNT(*) FROM response_actions r "
    "WHERE r.playbook_id = p.id AND r.status = 'Completed') AS completed_count "
    "FROM playbooks p LEFT JOIN users u ON u.id = p.created_by"
)
ACTION_SELECT_SQL = (
    "SELECT r.id, r.playbook_id, r.description, r.step_number, r.status, "
    "r.assigned_user_id, r.completion_date, u.username AS assigned_username, "
    "u.role AS assigned_role "
    "FROM response_actions r LEFT JOIN users u ON u.id = r.assigned_user_id"
)


class PlaybookConflict(Exception):
    """Raised when a request conflicts with the current playbook state."""


class NotFound(Exception):
    """Raised when a referenced playbook or action does not exist."""


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


def _positive_int(value, field):
    """Require a positive integer (booleans and floats are rejected)."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field} must be a positive integer.")
    return value


def _optional_user_id(value):
    """Validate an assigned_user_id that may be null (unassigned)."""
    return None if value is None else _positive_int(value, "assigned_user_id")


def _severity(value):
    """Validate a severity level."""
    if not isinstance(value, str) or value.strip() not in SEVERITIES:
        raise ValueError("severity must be Low, Medium, High or Critical.")
    return value.strip()


def _playbook(row):
    """Convert a playbook row into the API's playbook representation."""
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "incident_category": row["incident_category"],
        "severity": row["severity"],
        "created_by": row["created_by"],
        "created_by_username": row["created_by_username"],
        "created_at": row["created_at"],
        "action_count": row["action_count"],
        "completed_count": row["completed_count"],
    }


def _action(row):
    """Convert a response action row into the API's representation."""
    return {
        "id": row["id"],
        "playbook_id": row["playbook_id"],
        "description": row["description"],
        "step_number": row["step_number"],
        "status": row["status"],
        "assigned_user_id": row["assigned_user_id"],
        "assigned_user": None if row["assigned_username"] is None else {
            "id": row["assigned_user_id"],
            "username": row["assigned_username"],
            "role": row["assigned_role"],
        },
        "completion_date": row["completion_date"],
    }


def _fetch_playbook(db, playbook_id):
    """Return one playbook row with its action counts, or None."""
    return db.execute(PLAYBOOK_SELECT_SQL + " WHERE p.id = ?", (playbook_id,)).fetchone()


def _fetch_action(db, action_id):
    """Return one response action row, or None."""
    return db.execute(ACTION_SELECT_SQL + " WHERE r.id = ?", (action_id,)).fetchone()


def _playbook_with_actions(db, playbook_id):
    """Return the complete playbook with its actions ordered by step, or None."""
    row = _fetch_playbook(db, playbook_id)
    if row is None:
        return None
    playbook = _playbook(row)
    actions = db.execute(
        ACTION_SELECT_SQL + " WHERE r.playbook_id = ? ORDER BY r.step_number",
        (playbook_id,),
    ).fetchall()
    playbook["actions"] = [_action(action) for action in actions]
    return playbook


def _begin(db):
    """Start a write transaction so checks and writes happen atomically."""
    if db.in_transaction:
        db.commit()
    db.execute("BEGIN IMMEDIATE")


def _check_assignee(db, user_id):
    """Require the assignee to be an active ADMIN or ANALYST account."""
    if user_id is None:
        return
    row = (db.execute(
        "SELECT role, account_status FROM users WHERE id = ?", (user_id,)
    ).fetchone() if use_local_references() else lookup_user(user_id))
    if row is None:
        raise ValueError("assigned_user_id does not identify an existing user.")
    if row["account_status"] != "Active" or row["role"] not in ASSIGNABLE_ROLES:
        raise ValueError("assigned_user_id must identify an active ADMIN or ANALYST.")


def validate_new_action(data):
    """Validate and normalize the body used to add a response action."""
    if not isinstance(data, dict):
        raise ValueError("Each response action must be a JSON object.")
    unexpected = set(data) - ACTION_FIELDS
    if unexpected:
        raise ValueError(
            "Unsupported or server-managed field(s): " + ", ".join(sorted(unexpected))
        )
    missing = {"description", "step_number"} - set(data)
    if missing:
        raise ValueError("Missing required field(s): " + ", ".join(sorted(missing)))
    return {
        "description": _required_text(data, "description", 2000),
        "step_number": _positive_int(data["step_number"], "step_number"),
        "assigned_user_id": _optional_user_id(data.get("assigned_user_id")),
    }


def validate_new_playbook(data):
    """Validate the body used to create a playbook.

    name, description, incident_category and severity are required. An
    optional ``actions`` list creates the initial ordered response actions
    in the same transaction. created_by and created_at are server-managed.
    """
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")
    unexpected = set(data) - CREATE_FIELDS
    if unexpected:
        raise ValueError(
            "Unsupported or server-managed field(s): " + ", ".join(sorted(unexpected))
        )
    missing = PLAYBOOK_FIELDS - set(data)
    if missing:
        raise ValueError("Missing required field(s): " + ", ".join(sorted(missing)))

    playbook = {
        "name": _required_text(data, "name", 150),
        "description": _required_text(data, "description", 5000),
        "incident_category": _required_text(data, "incident_category", 100),
        "severity": _severity(data["severity"]),
    }
    actions = data.get("actions", [])
    if not isinstance(actions, list):
        raise ValueError("actions must be a list of response actions.")
    actions = [validate_new_action(action) for action in actions]
    steps = [action["step_number"] for action in actions]
    if len(steps) != len(set(steps)):
        raise ValueError("Each action in a playbook must have a distinct step_number.")
    return playbook, sorted(actions, key=lambda action: action["step_number"])


def _insert_action(db, playbook_id, action):
    """Insert one Pending response action and return its ID."""
    cursor = db.execute(
        """INSERT INTO response_actions
           (playbook_id, description, step_number, status, assigned_user_id)
           VALUES (?, ?, ?, 'Pending', ?)""",
        (playbook_id, action["description"], action["step_number"],
         action["assigned_user_id"]),
    )
    return cursor.lastrowid


def insert_playbook(db, data, creator_id):
    """Validate and insert a playbook (and any initial actions) atomically."""
    playbook, actions = validate_new_playbook(data)
    _begin(db)
    try:
        if db.execute(
            "SELECT 1 FROM playbooks WHERE lower(name) = lower(?)", (playbook["name"],)
        ).fetchone() is not None:
            raise PlaybookConflict("A playbook with this name already exists.")
        for action in actions:
            _check_assignee(db, action["assigned_user_id"])
        cursor = db.execute(
            """INSERT INTO playbooks
               (name, description, incident_category, severity, created_by)
               VALUES (?, ?, ?, ?, ?)""",
            (playbook["name"], playbook["description"], playbook["incident_category"],
             playbook["severity"], creator_id),
        )
        playbook_id = cursor.lastrowid
        for action in actions:
            _insert_action(db, playbook_id, action)
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return _playbook_with_actions(db, playbook_id)


def insert_action(db, playbook_id, data):
    """Validate and add a response action to an existing playbook."""
    action = validate_new_action(data)
    _begin(db)
    try:
        if db.execute("SELECT 1 FROM playbooks WHERE id = ?", (playbook_id,)).fetchone() is None:
            raise NotFound("Playbook not found.")
        _check_assignee(db, action["assigned_user_id"])
        if db.execute(
            "SELECT 1 FROM response_actions WHERE playbook_id = ? AND step_number = ?",
            (playbook_id, action["step_number"]),
        ).fetchone() is not None:
            raise PlaybookConflict(
                f"Step {action['step_number']} already exists in this playbook."
            )
        if db.execute(
            """SELECT 1 FROM response_actions
               WHERE playbook_id = ? AND step_number > ? AND status != 'Pending'""",
            (playbook_id, action["step_number"]),
        ).fetchone() is not None:
            raise PlaybookConflict(
                "A new step cannot be inserted before a step that has already started."
            )
        action_id = _insert_action(db, playbook_id, action)
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return _action(_fetch_action(db, action_id))


def validate_status_update(data):
    """Validate the format of an action update body (state rules come later)."""
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")
    if not data:
        raise ValueError("At least one update field is required.")
    unknown = set(data) - STATUS_UPDATE_FIELDS
    if unknown:
        raise ValueError(
            "Only status, assigned_user_id and completion_date can be updated. "
            "Unsupported field(s): " + ", ".join(sorted(unknown))
        )

    changes = {}
    if "status" in data:
        status = data["status"]
        if not isinstance(status, str) or status.strip() not in ACTION_LIFECYCLE:
            raise ValueError("status must be one of: " + ", ".join(ACTION_LIFECYCLE) + ".")
        changes["status"] = status.strip()
    if "assigned_user_id" in data:
        changes["assigned_user_id"] = _optional_user_id(data["assigned_user_id"])
    if "completion_date" in data:
        completed_at = _parse_timestamp(data["completion_date"], "completion_date")
        if completed_at > datetime.now(timezone.utc):
            raise ValueError("completion_date cannot be in the future.")
        changes["completion_date"] = completed_at
    return changes


def apply_status_rules(db, row, changes):
    """Apply lifecycle, ordering and completion rules to validated changes.

    Returns the column values to write. Raises PlaybookConflict when the
    change is invalid for the action's current state or step order, and
    ValueError when the assignee or completion date is invalid.
    """
    current_status = row["status"]
    if current_status == "Completed":
        raise PlaybookConflict("Completed actions are read-only.")

    updates = {}
    new_status = changes.get("status", current_status)
    if new_status != current_status:
        allowed = ACTION_LIFECYCLE[ACTION_LIFECYCLE.index(current_status) + 1]
        if new_status != allowed:
            raise PlaybookConflict(
                f"Invalid status transition from {current_status} to {new_status}. "
                f"The next allowed status is {allowed}."
            )
        unfinished = db.execute(
            """SELECT step_number FROM response_actions
               WHERE playbook_id = ? AND step_number < ? AND status != 'Completed'
               ORDER BY step_number""",
            (row["playbook_id"], row["step_number"]),
        ).fetchall()
        if unfinished:
            steps = ", ".join(str(step["step_number"]) for step in unfinished)
            raise PlaybookConflict(
                f"Earlier step(s) {steps} must be Completed before step "
                f"{row['step_number']} can move to {new_status}."
            )
        updates["status"] = new_status

    if "assigned_user_id" in changes:
        _check_assignee(db, changes["assigned_user_id"])
        updates["assigned_user_id"] = changes["assigned_user_id"]

    if "completion_date" in changes:
        if new_status != "Completed":
            raise PlaybookConflict(
                "completion_date can only be set when the action is Completed."
            )
        completed_at = changes["completion_date"]
        created = db.execute(
            "SELECT created_at FROM playbooks WHERE id = ?", (row["playbook_id"],)
        ).fetchone()
        created_at = _parse_timestamp(created["created_at"], "created_at")
        if completed_at.date() < created_at.date():
            raise ValueError("completion_date cannot be before the playbook's creation date.")
        updates["completion_date"] = _format_timestamp(completed_at)
    elif new_status == "Completed":
        updates["completion_date"] = _utc_now()
    return updates


@bp.post("")
@require_roles("ADMIN")
def create_playbook():
    """POST /playbooks: create an incident response playbook (ADMIN only).

    Author: Elias Ghanem.

    Requires name, description, incident_category and severity. An optional
    actions list (description, step_number, assigned_user_id) creates the
    initial ordered steps in the same transaction. created_by is the
    authenticated user. Returns 201, 400, 401, 403, 409 or 500.
    """
    db = get_db()
    try:
        playbook = insert_playbook(db, _json_object(), current_user()["id"])
    except PlaybookConflict as exc:
        return _error(str(exc), 409)
    except ValueError as exc:
        return _error(str(exc), 400)
    except sqlite3.DatabaseError:
        return _error("Unable to create playbook.", 500)

    response = jsonify({
        "status": "success",
        "message": "Playbook created successfully.",
        "playbook": playbook,
    })
    response.status_code = 201
    response.headers["Location"] = f"/playbooks/{playbook['id']}"
    return response


@bp.get("")
@require_roles("ADMIN", "ANALYST", "AUDITOR")
def list_playbooks():
    """GET /playbooks: list every playbook with its action counts.

    Author: Elias Ghanem.

    Each playbook includes action_count and completed_count.
    Returns 200, 401, 403 or 500.
    """
    try:
        rows = get_db().execute(PLAYBOOK_SELECT_SQL + " ORDER BY p.id DESC").fetchall()
    except sqlite3.DatabaseError:
        return _error("Unable to retrieve playbooks.", 500)

    playbooks = [_playbook(row) for row in rows]
    return jsonify({
        "status": "success",
        "count": len(playbooks),
        "playbooks": playbooks,
    }), 200


@bp.get("/<int:playbook_id>")
@require_roles("ADMIN", "ANALYST", "AUDITOR")
def get_playbook(playbook_id):
    """GET /playbooks/<id>: return a playbook with its ordered actions.

    Author: Elias Ghanem.

    Actions are ordered by step_number and include their status, assigned
    user and completion date. Returns 200, 401, 403, 404 or 500.
    """
    try:
        playbook = _playbook_with_actions(get_db(), playbook_id)
    except sqlite3.DatabaseError:
        return _error("Unable to retrieve playbook.", 500)
    if playbook is None:
        return _error("Playbook not found.", 404)
    return jsonify({"status": "success", "playbook": playbook}), 200


@bp.post("/<int:playbook_id>/actions")
@require_roles("ADMIN", "ANALYST")
def add_action(playbook_id):
    """POST /playbooks/<id>/actions: add a response step (ADMIN or ANALYST).

    Author: Elias Ghanem.

    Requires description and a positive step_number that is unique in the
    playbook; assigned_user_id (an active ADMIN or ANALYST) is optional.
    The status always starts as Pending.
    Returns 201, 400, 401, 403, 404, 409 or 500.
    """
    db = get_db()
    try:
        action = insert_action(db, playbook_id, _json_object())
    except NotFound as exc:
        return _error(str(exc), 404)
    except PlaybookConflict as exc:
        return _error(str(exc), 409)
    except ValueError as exc:
        return _error(str(exc), 400)
    except sqlite3.DatabaseError:
        return _error("Unable to add response action.", 500)

    response = jsonify({
        "status": "success",
        "message": "Response action added successfully.",
        "action": action,
    })
    response.status_code = 201
    response.headers["Location"] = f"/playbooks/{playbook_id}"
    return response


@actions_bp.put("/<int:action_id>/status")
@require_roles("ADMIN", "ANALYST")
def update_action_status(action_id):
    """PUT /actions/<id>/status: progress a response action (ADMIN or ANALYST).

    Author: Elias Ghanem.

    Editable fields: status, assigned_user_id and completion_date. Status
    may only advance one stage (Pending -> In Progress -> Completed), and
    only after every lower-numbered step in the playbook is Completed.
    Completing an action records its completion date automatically unless
    one is supplied. Completed actions are read-only.
    Returns 200, 400, 401, 403, 404, 409 or 500.
    """
    db = get_db()
    try:
        changes = validate_status_update(_json_object())
        _begin(db)
        try:
            row = _fetch_action(db, action_id)
            if row is None:
                raise NotFound("Response action not found.")
            updates = apply_status_rules(db, row, changes)
            if updates:
                # Every column comes from the fixed STATUS_UPDATE_FIELDS allowlist.
                assignments = ", ".join(f"{column} = ?" for column in updates)
                db.execute(
                    f"UPDATE response_actions SET {assignments} WHERE id = ?",
                    [*updates.values(), action_id],
                )
            db.commit()
        except BaseException:
            db.rollback()
            raise
        row = _fetch_action(db, action_id)
    except NotFound as exc:
        return _error(str(exc), 404)
    except PlaybookConflict as exc:
        return _error(str(exc), 409)
    except ValueError as exc:
        return _error(str(exc), 400)
    except sqlite3.DatabaseError:
        return _error("Unable to update response action.", 500)

    return jsonify({
        "status": "success",
        "message": "Response action updated successfully.",
        "action": _action(row),
    }), 200


@bp.delete("/<int:playbook_id>")
@require_roles("ADMIN")
def delete_playbook(playbook_id):
    """DELETE /playbooks/<id>: delete a playbook and its actions (ADMIN only).

    Author: Elias Ghanem.

    The playbook and all of its response actions are removed in one
    transaction. Returns 200, 401, 403, 404 or 500.
    """
    db = get_db()
    try:
        _begin(db)
        try:
            actions = db.execute(
                "DELETE FROM response_actions WHERE playbook_id = ?", (playbook_id,)
            ).rowcount
            if db.execute("DELETE FROM playbooks WHERE id = ?", (playbook_id,)).rowcount == 0:
                db.rollback()
                return _error("Playbook not found.", 404)
            db.commit()
        except BaseException:
            db.rollback()
            raise
    except sqlite3.DatabaseError:
        return _error("Unable to delete playbook.", 500)

    return jsonify({
        "status": "success",
        "message": "Playbook deleted successfully.",
        "deleted_id": playbook_id,
        "deleted_actions": actions,
    }), 200
