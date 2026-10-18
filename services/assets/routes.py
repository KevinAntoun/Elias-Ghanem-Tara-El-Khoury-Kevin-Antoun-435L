"""Asset Management API — Sprint 1.

Responsible student: Tara El Khoury.
All asset changes require ADMIN. Auditors can view all assets. Analysts can
read only assets referenced by incidents assigned to them.
"""

import ipaddress
import sqlite3

from flask import Blueprint, current_app, jsonify, request

from shared.auth import current_user, require_roles
from shared.database import get_db
from shared.reference_client import use_local_references, lookup_user, analyst_asset_ids

bp = Blueprint("assets", __name__, url_prefix="/assets")

CRITICALITIES = {"Low", "Medium", "High", "Critical"}
STATUSES = {"Active", "Inactive", "Under Maintenance"}
FIELDS = {
    "name", "asset_type", "ip_address", "operating_system", "department",
    "owner_id", "location", "criticality", "status",
}
REQUIRED = {"name", "asset_type", "owner_id", "criticality"}
TEXT_FIELDS = {
    "name", "asset_type", "operating_system", "department", "location",
}


def _error(message, status):
    return jsonify({"status": "error", "message": message}), status


def _asset(row):
    return dict(row)


def _validate_fields(data, *, creating=False):
    """Return (normalized_fields, error_message) for a JSON object."""
    if not isinstance(data, dict):
        return None, "A JSON object is required."
    if not data:
        return None, "At least one asset field is required."
    unknown = set(data) - FIELDS
    if unknown:
        return None, "Unsupported field(s): " + ", ".join(sorted(unknown))
    if creating:
        missing = REQUIRED - set(data)
        if missing:
            return None, "Missing required field(s): " + ", ".join(sorted(missing))

    cleaned = {}
    for key, value in data.items():
        if key in TEXT_FIELDS:
            if value is None and key not in ("name", "asset_type"):
                cleaned[key] = None
                continue
            if not isinstance(value, str):
                return None, f"{key} must be text."
            value = value.strip()
            if not value:
                return None, f"{key} cannot be empty."
            if len(value) > 255:
                return None, f"{key} must be 255 characters or fewer."
            cleaned[key] = value
        elif key == "owner_id":
            if type(value) is not int or value <= 0:
                return None, "owner_id must be a positive integer."
            cleaned[key] = value
        elif key == "criticality":
            if not isinstance(value, str) or value not in CRITICALITIES:
                return None, "criticality must be Low, Medium, High or Critical."
            cleaned[key] = value
        elif key == "status":
            if not isinstance(value, str) or value not in STATUSES:
                return None, "status must be Active, Inactive or Under Maintenance."
            cleaned[key] = value
        elif key == "ip_address":
            if value is None:
                cleaned[key] = None
            else:
                if not isinstance(value, str) or not value.strip():
                    return None, "ip_address must be a valid IPv4 or IPv6 address."
                try:
                    cleaned[key] = str(ipaddress.ip_address(value.strip()))
                except ValueError:
                    return None, "ip_address must be a valid IPv4 or IPv6 address."

    if creating:
        cleaned.setdefault("status", "Active")
    return cleaned, None


def _owner_exists(conn, owner_id):
    if not use_local_references():
        user = lookup_user(owner_id)
        return user is not None and user.get("account_status") == "Active"
    return conn.execute(
        "SELECT 1 FROM users WHERE id = ? AND account_status = 'Active'",
        (owner_id,),
    ).fetchone() is not None


def _analyst_can_see(conn, asset_id):
    """An analyst may view assets on incidents assigned to that analyst."""
    if not use_local_references():
        return asset_id in analyst_asset_ids(current_user()["id"])
    return conn.execute(
        """SELECT 1 FROM incidents
           WHERE affected_asset_id = ? AND assigned_analyst_id = ?
           LIMIT 1""",
        (asset_id, current_user()["id"]),
    ).fetchone() is not None


@bp.post("")
@require_roles("ADMIN")
def create_asset():
    """Create an organizational asset (administrator only)."""
    values, message = _validate_fields(request.get_json(silent=True), creating=True)
    if message:
        return _error(message, 400)
    conn = get_db()
    if not _owner_exists(conn, values["owner_id"]):
        return _error("owner_id must identify an active user.", 400)
    columns = list(values)
    placeholders = ", ".join("?" for _ in columns)
    sql = f"INSERT INTO assets ({', '.join(columns)}) VALUES ({placeholders})"
    try:
        cursor = conn.execute(sql, tuple(values[col] for col in columns))
        conn.commit()
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (cursor.lastrowid,)).fetchone()
    except sqlite3.IntegrityError:
        conn.rollback()
        return _error("Asset could not be created due to a relationship constraint.", 409)
    except sqlite3.DatabaseError:
        conn.rollback()
        return _error("Database unavailable while creating asset.", 500)
    return jsonify({"status": "success", "asset": _asset(row)}), 201


@bp.get("/search")
@require_roles("ADMIN", "ANALYST", "AUDITOR")
def search_assets():
    """Search by name, type, IP, department or criticality."""
    allowed = {"name", "asset_type", "ip_address", "department", "criticality"}
    filters = request.args.to_dict(flat=True)
    unknown = set(filters) - allowed
    if unknown:
        return _error("Unsupported search field(s): " + ", ".join(sorted(unknown)), 400)
    if not filters or any(not value.strip() for value in filters.values()):
        return _error("Provide at least one nonempty search parameter.", 400)
    conditions = []
    parameters = []
    for key, value in filters.items():
        if key in ("criticality", "ip_address"):
            conditions.append(f"a.{key} = ?")
            parameters.append(value)
        else:
            conditions.append(f"LOWER(a.{key}) LIKE ?")
            parameters.append("%" + value.lower() + "%")
    if current_user()["role"] == "ANALYST" and not use_local_references():
        ids = analyst_asset_ids(current_user()["id"])
        if not ids:
            return jsonify({"status": "success", "count": 0, "assets": []}), 200
        conditions.append("a.id IN (" + ",".join("?" for _ in ids) + ")")
        parameters.extend(ids)
    elif current_user()["role"] == "ANALYST":
        conditions.append(
            """EXISTS (SELECT 1 FROM incidents i
               WHERE i.affected_asset_id = a.id AND i.assigned_analyst_id = ?)"""
        )
        parameters.append(current_user()["id"])
    query = "SELECT a.* FROM assets a WHERE " + " AND ".join(conditions) + " ORDER BY a.id"
    rows = get_db().execute(query, parameters).fetchall()
    return jsonify({"status": "success", "count": len(rows), "assets": [_asset(r) for r in rows]}), 200


@bp.get("")
@require_roles("ADMIN", "AUDITOR")
def list_assets():
    """List all assets (administrator and auditor only)."""
    rows = get_db().execute("SELECT * FROM assets ORDER BY id").fetchall()
    return jsonify({"status": "success", "count": len(rows), "assets": [_asset(r) for r in rows]}), 200


@bp.get("/<int:asset_id>")
@require_roles("ADMIN", "ANALYST", "AUDITOR")
def get_asset(asset_id):
    """Return an asset; analysts require an assigned incident involving it."""
    conn = get_db()
    row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if row is None:
        return _error("Asset not found.", 404)
    if current_user()["role"] == "ANALYST" and not _analyst_can_see(conn, asset_id):
        return _error("You do not have permission to view this asset.", 403)
    return jsonify({"status": "success", "asset": _asset(row)}), 200


@bp.put("/<int:asset_id>")
@require_roles("ADMIN")
def update_asset(asset_id):
    """Update an existing organizational asset (administrator only)."""
    values, message = _validate_fields(request.get_json(silent=True))
    if message:
        return _error(message, 400)
    conn = get_db()
    existing = conn.execute("SELECT id FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if existing is None:
        return _error("Asset not found.", 404)
    if "owner_id" in values and not _owner_exists(conn, values["owner_id"]):
        return _error("owner_id must identify an active user.", 400)
    assignments = ", ".join(f"{key} = ?" for key in values)
    params = [*values.values(), asset_id]
    try:
        conn.execute(f"UPDATE assets SET {assignments} WHERE id = ?", params)
        conn.commit()
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    except sqlite3.IntegrityError:
        conn.rollback()
        return _error("Asset update violates a database relationship.", 409)
    except sqlite3.DatabaseError:
        conn.rollback()
        return _error("Database unavailable while updating asset.", 500)
    return jsonify({"status": "success", "asset": _asset(row)}), 200


@bp.delete("/<int:asset_id>")
@require_roles("ADMIN")
def delete_asset(asset_id):
    """Delete an unreferenced asset; never cascade-delete security records."""
    conn = get_db()
    if conn.execute("SELECT id FROM assets WHERE id = ?", (asset_id,)).fetchone() is None:
        return _error("Asset not found.", 404)
    try:
        conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        return _error("Asset is referenced by an incident or vulnerability and cannot be deleted.", 409)
    except sqlite3.DatabaseError:
        conn.rollback()
        return _error("Database unavailable while deleting asset.", 500)
    return jsonify({"status": "success", "message": "Asset deleted."}), 200
