"""Tests for all six Audit Logging endpoints and internal-service authorization.

Uses an isolated, in-memory SQLite database. No running servers are needed.
"""

import sqlite3
from pathlib import Path

import pytest

import services.audit.routes as audit_routes
import shared.auth as auth
from shared.app_factory import create_app


TEST_SECRET = "test-only-jwt-secret-" + "a" * 48
THREATS_SERVICE_SECRET = "test-only-audit-threats-secret-" + "b" * 48


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("AUDIT_TOKEN_THREATS", THREATS_SERVICE_SECRET)

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    schema_path = (
        Path(__file__).resolve().parents[1] / "database" / "schema.sql"
    )
    db.executescript(schema_path.read_text(encoding="utf-8"))

    db.executemany(
        """INSERT INTO users
           (full_name, username, email, password_hash, role, account_status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [
            ("Test Admin", "aud_admin", "aud_admin@example.com", "hash", "ADMIN", "Active"),
            ("Test Auditor", "aud_auditor", "aud_auditor@example.com", "hash", "AUDITOR", "Active"),
            ("Test Analyst", "aud_analyst", "aud_analyst@example.com", "hash", "ANALYST", "Active"),
            ("Test Employee", "aud_employee", "aud_employee@example.com", "hash", "EMPLOYEE", "Active"),
            ("Empty History", "aud_empty", "aud_empty@example.com", "hash", "EMPLOYEE", "Active"),
        ],
    )
    db.commit()

    monkeypatch.setattr(auth, "get_db", lambda: db)
    monkeypatch.setattr(audit_routes, "get_db", lambda: db)

    app = create_app("audit", [audit_routes.bp])
    app.config["TESTING"] = True
    result = {
        "client": app.test_client(),
        "db": db,
        "tokens": {
            "ADMIN": auth.create_access_token(1),
            "AUDITOR": auth.create_access_token(2),
            "ANALYST": auth.create_access_token(3),
            "EMPLOYEE": auth.create_access_token(4),
        },
    }
    yield result
    db.close()


def user_auth(api, role):
    return {"Authorization": f"Bearer {api['tokens'][role]}"}


def service_auth(secret=THREATS_SERVICE_SECRET, name="threats"):
    return {
        "Authorization": f"Service {secret}",
        "X-Service-Name": name,
    }


def sample_log(**changes):
    data = {
        "action": "THREAT_CREATED",
        "description": "Indicator registered.",
        "severity": "Information",
        "related_service": "threats",
    }
    data.update(changes)
    return data


def create_admin_log(api, **changes):
    response = api["client"].post(
        "/logs", json=sample_log(**changes), headers=user_auth(api, "ADMIN")
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["log"]


def test_admin_create_persists_with_verified_actor(api):
    log = create_admin_log(api)
    assert log["user_id"] == 1
    assert log["created_at"]
    stored = api["db"].execute("SELECT * FROM logs WHERE id=?", (log["id"],)).fetchone()
    assert stored["action"] == "THREAT_CREATED"


def test_admin_cannot_forge_actor_or_timestamp(api):
    for key, value in [("user_id", 3), ("id", 999), ("created_at", "now")]:
        response = api["client"].post(
            "/logs", json=sample_log(**{key: value}),
            headers=user_auth(api, "ADMIN")
        )
        assert response.status_code == 400


def test_create_rejects_invalid_severity_missing_action_and_content_type(api):
    client = api["client"]
    headers = user_auth(api, "ADMIN")
    assert client.post("/logs", json=sample_log(severity="High"), headers=headers).status_code == 400
    missing = sample_log()
    missing.pop("action")
    assert client.post("/logs", json=missing, headers=headers).status_code == 400
    assert client.post("/logs", data="wrong", content_type="text/plain", headers=headers).status_code == 400


def test_employee_and_unauthenticated_cannot_create(api):
    client = api["client"]
    assert client.post("/logs", json=sample_log(), headers=user_auth(api, "EMPLOYEE")).status_code == 403
    assert client.post("/logs", json=sample_log()).status_code == 401
    assert client.post("/logs", json=sample_log(), headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_internal_service_can_create_attributed_event(api):
    response = api["client"].post(
        "/logs", json=sample_log(user_id=3), headers=service_auth()
    )
    assert response.status_code == 201, response.get_json()
    assert response.json["log"]["user_id"] == 3
    assert response.json["log"]["related_service"] == "threats"


def test_internal_service_can_create_system_event(api):
    data = sample_log()
    data.pop("related_service")
    response = api["client"].post("/logs", json=data, headers=service_auth())
    assert response.status_code == 201
    assert response.json["log"]["user_id"] is None
    assert response.json["log"]["related_service"] == "threats"


def test_internal_bad_credentials_and_impersonation_rejected(api):
    client = api["client"]
    assert client.post("/logs", json=sample_log(), headers=service_auth("invalid")).status_code == 401
    assert client.post("/logs", json=sample_log(), headers=service_auth(name="users")).status_code == 401
    assert client.post("/logs", json=sample_log(related_service="users"), headers=service_auth()).status_code == 400
    assert client.post("/logs", json=sample_log(user_id=999), headers=service_auth()).status_code == 400


@pytest.mark.parametrize("role", ["ADMIN", "AUDITOR"])
def test_list_allowed_roles(api, role):
    create_admin_log(api)
    create_admin_log(api, action="LOGIN_FAILED", severity="Warning")
    response = api["client"].get("/logs", headers=user_auth(api, role))
    assert response.status_code == 200
    assert response.json["count"] == 2
    assert response.json["logs"][0]["action"] == "LOGIN_FAILED"


def test_list_empty_and_denied_roles(api):
    assert api["client"].get("/logs", headers=user_auth(api, "AUDITOR")).json["logs"] == []
    assert api["client"].get("/logs", headers=user_auth(api, "ANALYST")).status_code == 403
    assert api["client"].get("/logs").status_code == 401


@pytest.mark.parametrize("role", ["ADMIN", "AUDITOR", "ANALYST"])
def test_get_existing_log(api, role):
    log = create_admin_log(api)
    response = api["client"].get(f"/logs/{log['id']}", headers=user_auth(api, role))
    assert response.status_code == 200
    assert response.json["log"]["id"] == log["id"]


def test_get_missing_log_and_employee_denied(api):
    assert api["client"].get("/logs/999", headers=user_auth(api, "ADMIN")).status_code == 404
    assert api["client"].get("/logs/999", headers=user_auth(api, "EMPLOYEE")).status_code == 403


@pytest.mark.parametrize("role", ["ADMIN", "AUDITOR", "ANALYST"])
def test_search_filters(api, role):
    create_admin_log(api, action="THREAT_CREATED", severity="Critical")
    create_admin_log(api, action="LOGIN_FAILED", severity="Warning", related_service="users")
    url = "/logs/search?user_id=1&action=THREAT&severity=Critical&related_service=threats"
    response = api["client"].get(url, headers=user_auth(api, role))
    assert response.status_code == 200
    assert response.json["count"] == 1
    assert response.json["logs"][0]["action"] == "THREAT_CREATED"


def test_search_date_filters(api):
    log = create_admin_log(api)
    day = log["created_at"][:10]
    response = api["client"].get(
        f"/logs/search?from_date={day}&to_date={day}",
        headers=user_auth(api, "ANALYST"),
    )
    assert response.status_code == 200
    assert response.json["count"] == 1


def test_search_rejects_bad_filters(api):
    headers = user_auth(api, "ADMIN")
    for query in (
        "user_id=not-an-integer", "severity=High", "from_date=2026-02-30",
        "from_date=2026-10-20&to_date=2026-10-19", "unknown=1",
        "action=%27%20OR%201%3D1--&severity=High",
    ):
        assert api["client"].get(f"/logs/search?{query}", headers=headers).status_code == 400


def test_search_no_results_and_employee_denied(api):
    response = api["client"].get("/logs/search?action=not-present", headers=user_auth(api, "ANALYST"))
    assert response.status_code == 200
    assert response.json["logs"] == []
    assert api["client"].get("/logs/search", headers=user_auth(api, "EMPLOYEE")).status_code == 403


@pytest.mark.parametrize("role", ["ADMIN", "AUDITOR"])
def test_user_history_with_and_without_logs(api, role):
    create_admin_log(api)
    headers = user_auth(api, role)
    one = api["client"].get("/logs/user/1", headers=headers)
    empty = api["client"].get("/logs/user/5", headers=headers)
    assert one.status_code == 200 and one.json["count"] == 1
    assert empty.status_code == 200 and empty.json["logs"] == []


def test_user_history_denied_to_analyst(api):
    assert api["client"].get("/logs/user/1", headers=user_auth(api, "ANALYST")).status_code == 403


def test_delete_admin_preserves_separate_deletion_audit_trail(api):
    log = create_admin_log(api)
    response = api["client"].delete(f"/logs/{log['id']}", headers=user_auth(api, "ADMIN"))
    assert response.status_code == 200
    assert response.json["deleted_id"] == log["id"]
    rows = api["db"].execute("SELECT action, description FROM logs ORDER BY id").fetchall()
    assert len(rows) == 1
    assert rows[0]["action"] == "AUDIT_LOG_DELETED"
    assert str(log["id"]) in rows[0]["description"]


def test_delete_missing_and_denied(api):
    log = create_admin_log(api)
    assert api["client"].delete(f"/logs/{log['id']}", headers=user_auth(api, "AUDITOR")).status_code == 403
    assert api["client"].delete(f"/logs/{log['id']}", headers=user_auth(api, "ANALYST")).status_code == 403
    assert api["client"].delete("/logs/999", headers=user_auth(api, "ADMIN")).status_code == 404
    assert api["client"].get(f"/logs/{log['id']}", headers=user_auth(api, "ADMIN")).status_code == 200


def test_no_update_route(api):
    log = create_admin_log(api)
    response = api["client"].put(
        f"/logs/{log['id']}", json={"action": "CHANGED"},
        headers=user_auth(api, "ADMIN"),
    )
    assert response.status_code == 405
