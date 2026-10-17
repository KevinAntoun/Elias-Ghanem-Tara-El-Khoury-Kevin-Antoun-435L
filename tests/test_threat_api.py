"""Integration-style Flask tests for all six Threat Intelligence routes.

Run from the repository root:
    python -m pytest tests/test_threats_all_apis.py -v

The test database is in memory. These tests do not touch the team's SQLite file.
"""

import sqlite3
from pathlib import Path

import pytest
from flask import Flask

import shared.auth as auth
import services.threats.routes as threat_routes


TEST_JWT_SECRET = "only-for-test-use-" + "x" * 48


@pytest.fixture
def api(monkeypatch):
    """Provide real Flask HTTP requests backed by a private SQLite database."""
    monkeypatch.setenv("JWT_SECRET", TEST_JWT_SECRET)

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    schema_path = Path(__file__).resolve().parents[1] / "database" / "schema.sql"
    db.executescript(schema_path.read_text(encoding="utf-8"))

    for name, role in (
        ("test_admin", "ADMIN"),
        ("test_analyst", "ANALYST"),
        ("test_auditor", "AUDITOR"),
        ("test_employee", "EMPLOYEE"),
    ):
        db.execute(
            """
            INSERT INTO users
                (full_name, username, email, password_hash, role, account_status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (name, name, f"{name}@example.com", "unused-test-hash", role, "Active"),
        )
    db.commit()

    # Use the same isolated connection for JWT role lookups and threat queries.
    # This avoids dependence on DATABASE_PATH and leaves local data unchanged.
    monkeypatch.setattr(auth, "get_db", lambda: db)
    monkeypatch.setattr(threat_routes, "get_db", lambda: db)

    app = Flask(__name__)
    app.config["TESTING"] = True
    app.register_blueprint(threat_routes.bp)

    tokens = {
        "ADMIN": auth.create_access_token(1),
        "ANALYST": auth.create_access_token(2),
        "AUDITOR": auth.create_access_token(3),
        "EMPLOYEE": auth.create_access_token(4),
    }
    yield {"client": app.test_client(), "db": db, "tokens": tokens}
    db.close()


def headers(api, role="ADMIN"):
    """Return an Authorization header for a test user."""
    return {"Authorization": f"Bearer {api['tokens'][role]}"}


def sample_threat(**overrides):
    """Create a valid request body, optionally overriding some fields."""
    data = {
        "threat_type": "IP Address",
        "threat_value": "192.0.2.15",
        "description": "Suspicious login source",
        "severity": "High",
        "source": "Internal Monitoring",
    }
    data.update(overrides)
    return data


def seed_threat(api, *, threat_type="IP Address", threat_value="192.0.2.15",
                severity="High", source="Internal Monitoring"):
    """Insert fixtures directly so read/update/delete tests are independent."""
    cursor = api["db"].execute(
        """
        INSERT INTO threats (threat_type, threat_value, description, severity, source)
        VALUES (?, ?, ?, ?, ?)
        """,
        (threat_type, threat_value, "Fixture threat", severity, source),
    )
    api["db"].commit()
    return cursor.lastrowid


# 1. POST /threats

def test_create_threat_persists_and_returns_201(api):
    response = api["client"].post(
        "/threats", json=sample_threat(), headers=headers(api)
    )
    assert response.status_code == 201
    assert response.json["threat"]["id"] == 1
    assert response.json["threat"]["created_at"] is not None
    assert response.headers["Location"] == "/threats/1"
    row = api["db"].execute("SELECT * FROM threats WHERE id = 1").fetchone()
    assert row["threat_value"] == "192.0.2.15"


def test_create_duplicate_returns_409(api):
    seed_threat(api)
    response = api["client"].post(
        "/threats", json=sample_threat(), headers=headers(api)
    )
    assert response.status_code == 409
    assert api["db"].execute("SELECT COUNT(*) FROM threats").fetchone()[0] == 1


@pytest.mark.parametrize("invalid", [
    {"threat_type": "Unknown"},
    {"threat_value": "999.999.999.999"},
    {"severity": "Extreme"},
    {"severity": ""},
    {"description": 12},
    {"created_at": "forged timestamp"},
])
def test_create_rejects_invalid_fields(api, invalid):
    response = api["client"].post(
        "/threats", json=sample_threat(**invalid), headers=headers(api)
    )
    assert response.status_code == 400
    assert api["db"].execute("SELECT COUNT(*) FROM threats").fetchone()[0] == 0


@pytest.mark.parametrize("threat_type,threat_value,valid", [
    ("Domain", "Bad domain", False),
    ("Domain", "EXAMPLE.COM", True),
    ("File Hash", "abc123", False),
    ("File Hash", "A" * 64, True),
    ("Malware Signature", "YARA-rule-name", True),
])
def test_type_specific_validation(api, threat_type, threat_value, valid):
    response = api["client"].post(
        "/threats",
        json=sample_threat(threat_type=threat_type, threat_value=threat_value),
        headers=headers(api),
    )
    assert response.status_code == (201 if valid else 400)
    if valid and threat_type in {"Domain", "File Hash"}:
        assert response.json["threat"]["threat_value"] == threat_value.lower()


def test_post_requires_json_object(api):
    response = api["client"].post(
        "/threats", data="plain text", content_type="text/plain", headers=headers(api)
    )
    assert response.status_code == 400
    response = api["client"].post(
        "/threats", json=["not", "an", "object"], headers=headers(api)
    )
    assert response.status_code == 400


# 2. GET /threats

def test_list_threats_newest_first(api):
    seed_threat(api)
    seed_threat(api, threat_type="Domain", threat_value="example.com", severity="Medium")
    response = api["client"].get("/threats", headers=headers(api, "ANALYST"))
    assert response.status_code == 200
    assert response.json["count"] == 2
    assert [item["id"] for item in response.json["threats"]] == [2, 1]
    assert response.json["threats"][0]["created_at"] is not None


def test_list_empty_database(api):
    response = api["client"].get("/threats", headers=headers(api))
    assert response.status_code == 200
    assert response.json["count"] == 0
    assert response.json["threats"] == []


# 3. GET /threats/<id>

def test_get_threat_by_id(api):
    threat_id = seed_threat(api)
    response = api["client"].get(
        f"/threats/{threat_id}", headers=headers(api, "AUDITOR")
    )
    assert response.status_code == 200
    assert response.json["threat"]["threat_value"] == "192.0.2.15"


def test_get_missing_threat_returns_404(api):
    response = api["client"].get("/threats/999", headers=headers(api))
    assert response.status_code == 404


# 4. GET /threats/search

@pytest.mark.parametrize("query,expected_count", [
    ("threat_type=IP+Address", 1),
    ("threat_value=EXAMPLE", 1),
    ("severity=High", 1),
    ("source=FEED", 1),
    ("threat_type=Domain&severity=Medium", 1),
    ("threat_type=Domain&severity=Critical", 0),
])
def test_search_by_each_field_and_combinations(api, query, expected_count):
    seed_threat(api)
    seed_threat(
        api, threat_type="Domain", threat_value="example.com",
        severity="Medium", source="Threat Feed",
    )
    response = api["client"].get(
        "/threats/search?" + query, headers=headers(api, "ANALYST")
    )
    assert response.status_code == 200
    assert response.json["count"] == expected_count


def test_search_does_not_treat_percent_as_wildcard(api):
    seed_threat(api, source="Threat Feed")
    response = api["client"].get(
        "/threats/search?source=%25", headers=headers(api)
    )
    assert response.status_code == 200
    assert response.json["count"] == 0


@pytest.mark.parametrize("query", [
    "", "unknown=abc", "severity=Extreme", "threat_type=Unknown",
    "source=", "severity=High&severity=Low",
])
def test_search_invalid_filters_return_400(api, query):
    response = api["client"].get(
        "/threats/search" + ("?" + query if query else ""),
        headers=headers(api),
    )
    assert response.status_code == 400


# 5. PUT /threats/<id>

def test_update_threat_and_persist(api):
    threat_id = seed_threat(api)
    response = api["client"].put(
        f"/threats/{threat_id}",
        json={"description": "New investigation", "severity": "Critical", "source": "SOC"},
        headers=headers(api),
    )
    assert response.status_code == 200
    assert response.json["threat"]["severity"] == "Critical"
    row = api["db"].execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
    assert row["description"] == "New investigation"
    assert row["source"] == "SOC"
    assert row["threat_value"] == "192.0.2.15"


def test_update_can_clear_optional_fields(api):
    threat_id = seed_threat(api)
    response = api["client"].put(
        f"/threats/{threat_id}",
        json={"description": None, "source": "  "},
        headers=headers(api),
    )
    assert response.status_code == 200
    assert response.json["threat"]["description"] is None
    assert response.json["threat"]["source"] is None


@pytest.mark.parametrize("payload", [
    {}, {"severity": "Extreme"}, {"severity": None},
    {"threat_value": "another.example"}, {"threat_type": "Domain"},
    {"id": 123}, {"source": 22},
])
def test_update_rejects_invalid_payload(api, payload):
    threat_id = seed_threat(api)
    response = api["client"].put(
        f"/threats/{threat_id}", json=payload, headers=headers(api)
    )
    assert response.status_code == 400
    row = api["db"].execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
    assert row["severity"] == "High"


def test_update_missing_threat_returns_404(api):
    response = api["client"].put(
        "/threats/999", json={"severity": "Medium"}, headers=headers(api)
    )
    assert response.status_code == 404


# 6. DELETE /threats/<id>

def test_delete_threat_removes_record(api):
    threat_id = seed_threat(api)
    response = api["client"].delete(
        f"/threats/{threat_id}", headers=headers(api)
    )
    assert response.status_code == 200
    assert response.json["deleted_id"] == threat_id
    row = api["db"].execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
    assert row is None


def test_delete_missing_threat_returns_404(api):
    response = api["client"].delete("/threats/999", headers=headers(api))
    assert response.status_code == 404


# Authentication and authorization on ALL six routes

@pytest.mark.parametrize("method,path,body", [
    ("post", "/threats", sample_threat()),
    ("get", "/threats", None),
    ("get", "/threats/1", None),
    ("get", "/threats/search?severity=High", None),
    ("put", "/threats/1", {"severity": "Medium"}),
    ("delete", "/threats/1", None),
])
def test_all_endpoints_require_authentication(api, method, path, body):
    response = getattr(api["client"], method)(path, json=body)
    assert response.status_code == 401


@pytest.mark.parametrize("method,path,body", [
    ("post", "/threats", sample_threat()),
    ("put", "/threats/1", {"severity": "Medium"}),
    ("delete", "/threats/1", None),
])
@pytest.mark.parametrize("role", ["ANALYST", "AUDITOR", "EMPLOYEE"])
def test_non_admin_cannot_modify_threats(api, method, path, body, role):
    response = getattr(api["client"], method)(
        path, json=body, headers=headers(api, role)
    )
    assert response.status_code == 403
    assert api["db"].execute("SELECT COUNT(*) FROM threats").fetchone()[0] == 0


@pytest.mark.parametrize("path", [
    "/threats", "/threats/1", "/threats/search?severity=High"
])
def test_employee_cannot_read_threats(api, path):
    response = api["client"].get(path, headers=headers(api, "EMPLOYEE"))
    assert response.status_code == 403


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST", "AUDITOR"])
@pytest.mark.parametrize("path", [
    "/threats", "/threats/1", "/threats/search?severity=High"
])
def test_read_roles_are_allowed(api, role, path):
    seed_threat(api)
    response = api["client"].get(path, headers=headers(api, role))
    assert response.status_code == 200
