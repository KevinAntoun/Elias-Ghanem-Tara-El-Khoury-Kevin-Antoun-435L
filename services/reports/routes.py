"""Service 6 — Security Reports.

All six graded endpoints aggregate *real* records from the owning Flask
services through HTTP. This module never reads another service's tables.

An ADMIN or AUDITOR's verified JWT is forwarded to the source services;
the source services must independently verify authorization. If a source
is unavailable or returns an incomplete/malformed collection, the report
fails instead of presenting fabricated or partial statistics.

GET /reports/dependencies may already exist in your original scaffold as
an optional health demo. Its presence does not count toward the six APIs.
"""

from collections import Counter

import requests
from flask import Blueprint, jsonify, request

from shared.auth import require_roles
from shared.service_client import request_json


bp = Blueprint("reports", __name__, url_prefix="/reports")

# Explicit source contracts: a GET on each service returns an object with a
# collection under the indicated key, e.g. {"users": [...]}.
COLLECTIONS = {
    "users": ("users", "/users", "users"),
    "assets": ("assets", "/assets", "assets"),
    "incidents": ("incidents", "/incidents", "incidents"),
    "threats": ("threats", "/threats", "threats"),
    "vulnerabilities": ("vulnerabilities", "/vulnerabilities", "vulnerabilities"),
    "logs": ("audit", "/logs", "logs"),
}

# Agree with the Users and Audit service owners on these canonical event names.
# This service does not infer login attempts from unrelated activity logs.
LOGIN_SUCCESS_ACTIONS = frozenset({"LOGIN_SUCCESS"})
LOGIN_FAILED_ACTIONS = frozenset({"LOGIN_FAILED"})


class ReportDependencyError(Exception):
    """A required source service could not supply trustworthy report data."""

    def __init__(self, service, message, status_code=502):
        self.service = service
        self.message = message
        self.status_code = status_code
        super().__init__(f"{service}: {message}")


def _access_token():
    """Return the JWT already validated by require_roles()."""
    return request.headers["Authorization"].split()[1]


def _read_collection(name, token):
    """Fetch one complete authorized collection over HTTP.

    Never interpret a missing list, an incomplete/paginated list, or an
    upstream error as an empty collection: that would corrupt report totals.
    """
    service, path, field = COLLECTIONS[name]
    try:
        document = request_json(service, path, token=token)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        raise ReportDependencyError(service, "Source service unavailable.", 503) from None
    except requests.exceptions.RequestException:
        raise ReportDependencyError(service, "Source service request failed.") from None
    except (ValueError, TypeError):
        raise ReportDependencyError(service, "Source service sent invalid JSON.") from None

    if not isinstance(document, dict) or document.get("status") == "error":
        raise ReportDependencyError(service, "Source service sent an invalid response.")

    rows = document.get(field)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ReportDependencyError(service, f"Expected a '{field}' list of objects.")

    # A source returning only page 1 is not an acceptable basis for totals.
    if document.get("next") or document.get("next_page"):
        raise ReportDependencyError(service, "Source returned a paginated response.")
    page = document.get("pagination")
    if isinstance(page, dict) and (page.get("next") or page.get("has_next")):
        raise ReportDependencyError(service, "Source returned a paginated response.")
    for count_field in ("count", "total", "total_count"):
        reported_count = document.get(count_field)
        if reported_count is not None and (
            type(reported_count) is not int or reported_count != len(rows)
        ):
            raise ReportDependencyError(service, "Source returned an incomplete collection.")

    return rows


def _require_fields(rows, service, *fields):
    """Reject schema mismatches instead of silently counting blank values."""
    if any(any(field not in row for field in fields) for row in rows):
        raise ReportDependencyError(service, "Source records are missing required fields.")


def _count_by(rows, field):
    """Return counts by a required text field."""
    return dict(sorted(Counter(row[field] for row in rows).items()))


def _report(build):
    """Handle source failures consistently without exposing server secrets."""
    try:
        output = build(_access_token())
    except ReportDependencyError as exc:
        return jsonify({
            "status": "error",
            "message": f"Cannot generate report: {exc.message}",
            "dependency": exc.service,
        }), exc.status_code
    return jsonify({"status": "success", **output}), 200


@bp.get("/summary")
@require_roles("ADMIN", "AUDITOR")
def summary_report():
    """GET /reports/summary: counts of users, assets, open incidents, critical threats."""
    def build(token):
        users = _read_collection("users", token)
        assets = _read_collection("assets", token)
        incidents = _read_collection("incidents", token)
        threats = _read_collection("threats", token)
        _require_fields(incidents, "incidents", "status")
        _require_fields(threats, "threats", "severity")
        return {"summary": {
            "total_users": len(users),
            "total_assets": len(assets),
            "open_incidents": sum(i["status"] == "Open" for i in incidents),
            "critical_threats": sum(t["severity"] == "Critical" for t in threats),
        }}
    return _report(build)


@bp.get("/incidents")
@require_roles("ADMIN", "AUDITOR")
def incidents_report():
    """GET /reports/incidents: incident totals grouped by severity and status."""
    def build(token):
        incidents = _read_collection("incidents", token)
        _require_fields(incidents, "incidents", "severity", "status")
        return {"incidents": {
            "total": len(incidents),
            "by_severity": _count_by(incidents, "severity"),
            "by_status": _count_by(incidents, "status"),
        }}
    return _report(build)


@bp.get("/assets")
@require_roles("ADMIN", "AUDITOR")
def assets_report():
    """GET /reports/assets: asset totals, criticality, and type distribution."""
    def build(token):
        assets = _read_collection("assets", token)
        _require_fields(assets, "assets", "criticality", "asset_type")
        return {"assets": {
            "total": len(assets),
            "critical_assets": sum(a["criticality"] == "Critical" for a in assets),
            "by_type": _count_by(assets, "asset_type"),
        }}
    return _report(build)


@bp.get("/threats")
@require_roles("ADMIN", "AUDITOR")
def threats_report():
    """GET /reports/threats: severity/type distributions and five newest indicators."""
    def build(token):
        threats = _read_collection("threats", token)
        _require_fields(threats, "threats", "severity", "threat_type", "created_at", "id")
        recent = sorted(
            threats,
            key=lambda row: (str(row["created_at"] or ""), row["id"]),
            reverse=True,
        )[:5]
        return {"threats": {
            "total": len(threats),
            "by_severity": _count_by(threats, "severity"),
            "by_type": _count_by(threats, "threat_type"),
            "recently_added": recent,
        }}
    return _report(build)


@bp.get("/vulnerabilities")
@require_roles("ADMIN", "AUDITOR")
def vulnerabilities_report():
    """GET /reports/vulnerabilities: totals, severity, status, and critical count."""
    def build(token):
        vulnerabilities = _read_collection("vulnerabilities", token)
        _require_fields(vulnerabilities, "vulnerabilities", "severity", "status")
        return {"vulnerabilities": {
            "total": len(vulnerabilities),
            "critical_vulnerabilities": sum(
                v["severity"] == "Critical" for v in vulnerabilities
            ),
            "by_severity": _count_by(vulnerabilities, "severity"),
            "by_status": _count_by(vulnerabilities, "status"),
        }}
    return _report(build)


@bp.get("/activity")
@require_roles("ADMIN", "AUDITOR")
def activity_report():
    """GET /reports/activity: activity counts from actual Audit service events.

    Login event action names must match the shared team event contract:
    LOGIN_SUCCESS and LOGIN_FAILED. Other action names are not assumed to
    represent logins.
    """
    def build(token):
        logs = _read_collection("logs", token)
        _require_fields(logs, "audit", "action")
        actions = Counter(row["action"] for row in logs)
        return {"activity": {
            "total_activities": len(logs),
            "login_attempts": sum(actions.get(a, 0) for a in (
                LOGIN_SUCCESS_ACTIONS | LOGIN_FAILED_ACTIONS
            )),
            "failed_logins": sum(actions.get(a, 0) for a in LOGIN_FAILED_ACTIONS),
            "common_actions": dict(sorted(actions.items(), key=lambda item: (-item[1], item[0]))[:5]),
        }}
    return _report(build)

@bp.get("/dependencies")
def dependency_health():
    """Original non-graded demo: check Users and Assets health over HTTP.

    This is not one of the six required Security Reports endpoints.
    """
    try:
        users_health = request_json("users", "/health")
        assets_health = request_json("assets", "/health")
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return jsonify({"status": "error", "message": "Dependency unavailable."}), 503
    except (requests.exceptions.RequestException, ValueError, TypeError):
        return jsonify({"status": "error", "message": "Dependency health check failed."}), 502
    return jsonify({
        "service": "reports",
        "dependencies": {"users": users_health, "assets": assets_health},
    }), 200

