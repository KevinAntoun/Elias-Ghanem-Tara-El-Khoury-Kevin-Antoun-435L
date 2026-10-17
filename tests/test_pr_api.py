"""Service 6 tests: six reports, roles, authorization and dependency failures.

Each upstream HTTP API is replaced with a deterministic response fixture;
production routes still use shared.service_client.request_json over HTTP.
"""

from copy import deepcopy
from pathlib import Path
import sqlite3

import pytest
import requests

import shared.auth as auth
import services.reports.routes as reports
from shared.app_factory import create_app


PATHS = (
    "/reports/summary",
    "/reports/incidents",
    "/reports/assets",
    "/reports/threats",
    "/reports/vulnerabilities",
    "/reports/activity",
)


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "local-test-secret-" + "s" * 48)

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    schema_path = Path(__file__).resolve().parents[1] / "database" / "schema.sql"
    db.executescript(schema_path.read_text(encoding="utf-8"))

    for role in ("ADMIN", "AUDITOR", "ANALYST", "EMPLOYEE"):
        name = role.lower()
        db.execute(
            """INSERT INTO users
               (full_name, username, email, password_hash, role, account_status)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, name, name + "@example.com", "unused-test-hash", role, "Active"),
        )
    db.commit()
    monkeypatch.setattr(auth, "get_db", lambda: db)

    source_data = {
        "users": [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}],
        "assets": [
            {"id": 1, "asset_type": "Server", "criticality": "Critical"},
            {"id": 2, "asset_type": "Server", "criticality": "High"},
            {"id": 3, "asset_type": "Workstation", "criticality": "Low"},
        ],
        "incidents": [
            {"id": 1, "severity": "High", "status": "Open"},
            {"id": 2, "severity": "Critical", "status": "Open"},
            {"id": 3, "severity": "Medium", "status": "Resolved"},
        ],
        "threats": [
            {"id": 1, "threat_type": "IP Address", "severity": "High", "created_at": "2026-10-10 09:00:00"},
            {"id": 2, "threat_type": "Domain", "severity": "Critical", "created_at": "2026-10-11 09:00:00"},
            {"id": 3, "threat_type": "File Hash", "severity": "Low", "created_at": "2026-10-12 09:00:00"},
            {"id": 4, "threat_type": "Domain", "severity": "Critical", "created_at": "2026-10-13 09:00:00"},
            {"id": 5, "threat_type": "Malware Signature", "severity": "Medium", "created_at": "2026-10-14 09:00:00"},
            {"id": 6, "threat_type": "IP Address", "severity": "High", "created_at": "2026-10-15 09:00:00"},
        ],
        "vulnerabilities": [
            {"id": 1, "severity": "Critical", "status": "Open"},
            {"id": 2, "severity": "High", "status": "In Progress"},
            {"id": 3, "severity": "Critical", "status": "Resolved"},
        ],
        "audit": [
            {"id": 1, "action": "LOGIN_SUCCESS"},
            {"id": 2, "action": "LOGIN_FAILED"},
            {"id": 3, "action": "THREAT_CREATED"},
            {"id": 4, "action": "THREAT_CREATED"},
            {"id": 5, "action": "ASSET_UPDATED"},
            {"id": 6, "action": "LOGIN_SUCCESS"},
        ],
    }

    field_by_service = {
        "users": "users", "assets": "assets", "incidents": "incidents",
        "threats": "threats", "vulnerabilities": "vulnerabilities", "audit": "logs",
    }
    overrides = {}
    calls = []

    def fake_request_json(service, path, *, token=None, method="GET", json_body=None):
        calls.append((service, path, token, method))
        assert method == "GET"
        assert token is not None
        assert path == ("/logs" if service == "audit" else "/" + service)
        if service in overrides:
            replacement = overrides[service]
            if isinstance(replacement, Exception):
                raise replacement
            return deepcopy(replacement)
        key = field_by_service[service]
        rows = deepcopy(source_data[service])
        return {"status": "success", "count": len(rows), key: rows}

    monkeypatch.setattr(reports, "request_json", fake_request_json)

    app = create_app("reports", [reports.bp])
    app.config["TESTING"] = True

    client = app.test_client()
    tokens = {role: auth.create_access_token(i) for i, role in enumerate(
        ("ADMIN", "AUDITOR", "ANALYST", "EMPLOYEE"), start=1
    )}

    yield {"client": client, "tokens": tokens, "calls": calls,
           "sources": source_data, "overrides": overrides}
    db.close()


def get_report(api, path, role="ADMIN"):
    token = api["tokens"][role]
    return api["client"].get(path, headers={"Authorization": f"Bearer {token}"})


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("role", ("ADMIN", "AUDITOR"))
def test_authorized_roles_can_get_every_report(api, path, role):
    response = get_report(api, path, role)
    assert response.status_code == 200
    assert response.json["status"] == "success"


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("role", ("ANALYST", "EMPLOYEE"))
def test_other_roles_cannot_read_reports(api, path, role):
    response = get_report(api, path, role)
    assert response.status_code == 403
    assert api["calls"] == []


@pytest.mark.parametrize("path", PATHS)
def test_no_token_is_denied(api, path):
    response = api["client"].get(path)
    assert response.status_code == 401
    assert api["calls"] == []


def test_invalid_token_is_denied(api):
    response = api["client"].get(
        "/reports/summary", headers={"Authorization": "Bearer not-a-token"}
    )
    assert response.status_code == 401


def test_summary_counts(api):
    body = get_report(api, "/reports/summary").json["summary"]
    assert body == {
        "total_users": 4,
        "total_assets": 3,
        "open_incidents": 2,
        "critical_threats": 2,
    }


def test_incidents_grouping(api):
    body = get_report(api, "/reports/incidents").json["incidents"]
    assert body["total"] == 3
    assert body["by_status"] == {"Open": 2, "Resolved": 1}
    assert body["by_severity"] == {"Critical": 1, "High": 1, "Medium": 1}


def test_assets_grouping(api):
    body = get_report(api, "/reports/assets").json["assets"]
    assert body["total"] == 3
    assert body["critical_assets"] == 1
    assert body["by_type"] == {"Server": 2, "Workstation": 1}


def test_threats_report_and_recency(api):
    body = get_report(api, "/reports/threats").json["threats"]
    assert body["total"] == 6
    assert body["by_severity"]["Critical"] == 2
    assert body["by_type"]["Domain"] == 2
    assert len(body["recently_added"]) == 5
    assert [t["id"] for t in body["recently_added"]] == [6, 5, 4, 3, 2]


def test_vulnerability_report(api):
    body = get_report(api, "/reports/vulnerabilities").json["vulnerabilities"]
    assert body["total"] == 3
    assert body["critical_vulnerabilities"] == 2
    assert body["by_status"] == {"In Progress": 1, "Open": 1, "Resolved": 1}


def test_activity_report_uses_real_audit_actions(api):
    body = get_report(api, "/reports/activity").json["activity"]
    assert body["total_activities"] == 6
    assert body["login_attempts"] == 3
    assert body["failed_logins"] == 1
    assert body["common_actions"]["THREAT_CREATED"] == 2


def test_forwarded_verified_token(api):
    get_report(api, "/reports/summary", "AUDITOR")
    assert len(api["calls"]) == 4
    assert all(call[2] == api["tokens"]["AUDITOR"] for call in api["calls"])


def test_unavailable_source_returns_503_not_fake_zero(api):
    api["overrides"]["assets"] = requests.exceptions.ConnectionError("service offline")
    response = get_report(api, "/reports/assets")
    assert response.status_code == 503
    assert response.json["dependency"] == "assets"
    assert "assets" not in response.json


def test_invalid_upstream_shape_returns_502(api):
    api["overrides"]["audit"] = {"status": "success", "data": []}
    response = get_report(api, "/reports/activity")
    assert response.status_code == 502
    assert response.json["dependency"] == "audit"


def test_paginated_collection_is_rejected(api):
    api["overrides"]["threats"] = {
        "status": "success", "threats": [], "count": 0,
        "pagination": {"has_next": True},
    }
    response = get_report(api, "/reports/threats")
    assert response.status_code == 502


def test_incomplete_count_is_rejected(api):
    api["overrides"]["assets"] = {"status": "success", "assets": [], "count": 15}
    response = get_report(api, "/reports/assets")
    assert response.status_code == 502


def test_missing_critical_fields_is_rejected(api):
    api["sources"]["assets"] = [{"id": 1, "asset_type": "Server"}]
    response = get_report(api, "/reports/assets")
    assert response.status_code == 502


@pytest.mark.parametrize("path", PATHS)
def test_empty_sources_return_zero_counts(api, path):
    for key in api["sources"]:
        api["sources"][key] = []
    response = get_report(api, path)
    assert response.status_code == 200
