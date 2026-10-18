"""Flask tests for all six Vulnerability Management routes (Elias Ghanem).

Run from the repository root:
    python -m pytest tests/test_vulnerabilities_api.py -v

The test database is in memory. These tests do not touch the team's SQLite file.
"""

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import services.vulnerabilities.routes as vulnerability_routes
import shared.auth as auth
from shared.app_factory import create_app


TEST_JWT_SECRET = "only-for-test-use-" + "v" * 48


@pytest.fixture
def api(monkeypatch):
    """Provide real Flask HTTP requests backed by a private SQLite database."""
    monkeypatch.setenv("JWT_SECRET", TEST_JWT_SECRET)

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    schema_path = Path(__file__).resolve().parents[1] / "database" / "schema.sql"
    db.executescript(schema_path.read_text(encoding="utf-8"))

    for name, role in (
        ("vuln_admin", "ADMIN"),
        ("vuln_analyst", "ANALYST"),
        ("vuln_auditor", "AUDITOR"),
        ("vuln_employee", "EMPLOYEE"),
    ):
        db.execute(
            """INSERT INTO users
               (full_name, username, email, password_hash, role, account_status)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, name, f"{name}@example.com", "unused-test-hash", role, "Active"),
        )
    db.executemany(
        """INSERT INTO assets (name, asset_type, ip_address, owner_id, criticality)
           VALUES (?, ?, ?, ?, ?)""",
        [
            ("web-server-01", "Server", "10.0.0.10", 1, "Critical"),
            ("hr-laptop-07", "Workstation", "10.0.1.27", 1, "Medium"),
        ],
    )
    db.commit()

    monkeypatch.setattr(auth, "get_db", lambda: db)
    monkeypatch.setattr(vulnerability_routes, "get_db", lambda: db)

    app = create_app("vulnerabilities", [vulnerability_routes.bp])
    app.config["TESTING"] = True
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


def sample_vulnerability(**overrides):
    """Return a valid creation body, optionally overriding some fields."""
    data = {
        "title": "XZ Utils backdoor",
        "description": "Malicious code in liblzma allows remote access via sshd.",
        "cve_identifier": "CVE-2024-3094",
        "cvss_score": 10.0,
        "severity": "Critical",
        "affected_asset_id": 1,
        "discovery_source": "Vulnerability Scan",
    }
    data.update(overrides)
    return data


def seed(api, *, cve="CVE-2024-3094", score=10.0, severity="Critical",
         asset_id=1, status="Open", created_at=None):
    """Insert a fixture directly so read/update/delete tests are independent."""
    columns = ["title", "description", "cve_identifier", "cvss_score", "severity",
               "affected_asset_id", "discovery_source", "status"]
    values = ["Fixture", "Fixture vulnerability", cve, score, severity,
              asset_id, "Penetration Test", status]
    if created_at is not None:
        columns.append("created_at")
        values.append(created_at)
    cursor = api["db"].execute(
        f"INSERT INTO vulnerabilities ({', '.join(columns)}) "
        f"VALUES ({', '.join('?' for _ in columns)})",
        values,
    )
    api["db"].commit()
    return cursor.lastrowid


def stored(api, vulnerability_id):
    return api["db"].execute(
        "SELECT * FROM vulnerabilities WHERE id = ?", (vulnerability_id,)
    ).fetchone()


def count(api):
    return api["db"].execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]


# 1. POST /vulnerabilities

def test_create_persists_and_returns_201(api):
    response = api["client"].post(
        "/vulnerabilities", json=sample_vulnerability(), headers=headers(api)
    )
    assert response.status_code == 201, response.get_json()
    body = response.json["vulnerability"]
    assert body["id"] == 1
    assert body["status"] == "Open"
    assert body["created_at"] is not None
    assert body["resolution_date"] is None
    assert body["affected_asset"] == {
        "id": 1, "name": "web-server-01", "asset_type": "Server", "criticality": "Critical",
    }
    assert response.headers["Location"] == "/vulnerabilities/1"
    row = stored(api, 1)
    assert row["cve_identifier"] == "CVE-2024-3094"
    assert row["severity"] == "Critical"


def test_create_normalizes_cve_and_integer_score(api):
    response = api["client"].post(
        "/vulnerabilities",
        json=sample_vulnerability(cve_identifier=" cve-2021-44228 ", cvss_score=10),
        headers=headers(api),
    )
    assert response.status_code == 201
    assert response.json["vulnerability"]["cve_identifier"] == "CVE-2021-44228"
    assert response.json["vulnerability"]["cvss_score"] == 10.0


@pytest.mark.parametrize("field", sorted(vulnerability_routes.CREATE_FIELDS))
def test_create_requires_every_field(api, field):
    data = sample_vulnerability()
    data.pop(field)
    response = api["client"].post("/vulnerabilities", json=data, headers=headers(api))
    assert response.status_code == 400
    assert field in response.json["message"]
    assert count(api) == 0


@pytest.mark.parametrize("invalid", [
    {"title": ""},
    {"title": "   "},
    {"description": 42},
    {"cve_identifier": "CVE-24-1"},
    {"cve_identifier": "not-a-cve"},
    {"cve_identifier": "CVE-2024-３０９４"},
    {"cvss_score": 11},
    {"cvss_score": 0},
    {"cvss_score": -1.5},
    {"cvss_score": "7.5"},
    {"cvss_score": True},
    {"cvss_score": 9.85},
    {"severity": "Extreme"},
    {"severity": None},
    {"cvss_score": 9.8, "severity": "High"},
    {"cvss_score": 3.9, "severity": "Medium"},
    {"affected_asset_id": "1"},
    {"affected_asset_id": 0},
    {"affected_asset_id": True},
    {"discovery_source": 5},
    {"status": "Closed"},
    {"resolution_date": "2026-01-01"},
    {"id": 99},
    {"created_at": "forged"},
])
def test_create_rejects_invalid_fields(api, invalid):
    response = api["client"].post(
        "/vulnerabilities", json=sample_vulnerability(**invalid), headers=headers(api)
    )
    assert response.status_code == 400
    assert response.json["status"] == "error"
    assert count(api) == 0


@pytest.mark.parametrize("score,severity", [
    (0.1, "Low"), (3.9, "Low"), (4.0, "Medium"), (6.9, "Medium"),
    (7.0, "High"), (8.9, "High"), (9.0, "Critical"), (10.0, "Critical"),
])
def test_create_accepts_cvss_rating_boundaries(api, score, severity):
    response = api["client"].post(
        "/vulnerabilities",
        json=sample_vulnerability(cvss_score=score, severity=severity),
        headers=headers(api),
    )
    assert response.status_code == 201


def test_create_rejects_unknown_asset(api):
    response = api["client"].post(
        "/vulnerabilities", json=sample_vulnerability(affected_asset_id=999),
        headers=headers(api),
    )
    assert response.status_code == 400
    assert count(api) == 0


def test_create_rejects_duplicate_cve_on_same_asset(api):
    seed(api)
    response = api["client"].post(
        "/vulnerabilities", json=sample_vulnerability(), headers=headers(api)
    )
    assert response.status_code == 409
    assert count(api) == 1


def test_same_cve_allowed_on_other_asset_or_after_closing(api):
    seed(api, status="Closed")
    client = api["client"]
    assert client.post(
        "/vulnerabilities", json=sample_vulnerability(), headers=headers(api)
    ).status_code == 201
    assert client.post(
        "/vulnerabilities", json=sample_vulnerability(affected_asset_id=2),
        headers=headers(api),
    ).status_code == 201
    assert count(api) == 3


def test_create_requires_json_object(api):
    client = api["client"]
    assert client.post(
        "/vulnerabilities", data="plain text", content_type="text/plain",
        headers=headers(api),
    ).status_code == 400
    assert client.post(
        "/vulnerabilities", json=["not", "an", "object"], headers=headers(api)
    ).status_code == 400


# 2. GET /vulnerabilities

def test_list_newest_first_with_asset_details(api):
    seed(api)
    seed(api, cve="CVE-2023-4863", score=8.8, severity="High", asset_id=2)
    response = api["client"].get("/vulnerabilities", headers=headers(api, "AUDITOR"))
    assert response.status_code == 200
    assert response.json["count"] == 2
    items = response.json["vulnerabilities"]
    assert [item["id"] for item in items] == [2, 1]
    assert items[0]["severity"] == "High"
    assert items[0]["status"] == "Open"
    assert items[0]["affected_asset"]["name"] == "hr-laptop-07"


def test_list_empty_database(api):
    response = api["client"].get("/vulnerabilities", headers=headers(api, "ANALYST"))
    assert response.status_code == 200
    assert response.json["count"] == 0
    assert response.json["vulnerabilities"] == []


# 3. GET /vulnerabilities/<id>

def test_get_existing_vulnerability(api):
    vulnerability_id = seed(api)
    response = api["client"].get(
        f"/vulnerabilities/{vulnerability_id}", headers=headers(api, "ANALYST")
    )
    assert response.status_code == 200
    body = response.json["vulnerability"]
    assert body["cve_identifier"] == "CVE-2024-3094"
    assert set(vulnerability_routes.VULNERABILITY_COLUMNS) <= set(body)


def test_get_missing_vulnerability_returns_404(api):
    response = api["client"].get("/vulnerabilities/999", headers=headers(api))
    assert response.status_code == 404
    assert response.json == {"status": "error", "message": "Vulnerability not found."}


# 4. PUT /vulnerabilities/<id>

def test_analyst_updates_description_score_and_severity(api):
    vulnerability_id = seed(api)
    response = api["client"].put(
        f"/vulnerabilities/{vulnerability_id}",
        json={"description": "Confirmed on host.", "cvss_score": 7.5, "severity": "High"},
        headers=headers(api, "ANALYST"),
    )
    assert response.status_code == 200, response.get_json()
    row = stored(api, vulnerability_id)
    assert row["description"] == "Confirmed on host."
    assert row["cvss_score"] == 7.5
    assert row["severity"] == "High"
    assert row["title"] == "Fixture"


@pytest.mark.parametrize("payload", [
    {"cvss_score": 5.0},
    {"severity": "Low"},
    {"cvss_score": 9.1, "severity": "High"},
])
def test_update_keeps_severity_consistent_with_cvss(api, payload):
    vulnerability_id = seed(api)
    response = api["client"].put(
        f"/vulnerabilities/{vulnerability_id}", json=payload, headers=headers(api)
    )
    assert response.status_code == 400
    row = stored(api, vulnerability_id)
    assert (row["cvss_score"], row["severity"]) == (10.0, "Critical")


def test_full_lifecycle_records_resolution_date(api):
    vulnerability_id = seed(api)
    client = api["client"]
    path = f"/vulnerabilities/{vulnerability_id}"
    for status in ("Under Investigation", "In Progress"):
        response = client.put(path, json={"status": status}, headers=headers(api, "ANALYST"))
        assert response.status_code == 200
        assert response.json["vulnerability"]["resolution_date"] is None

    resolved = client.put(path, json={"status": "Resolved"}, headers=headers(api, "ANALYST"))
    assert resolved.status_code == 200
    resolution_date = resolved.json["vulnerability"]["resolution_date"]
    assert resolution_date is not None and resolution_date.endswith("Z")

    closed = client.put(path, json={"status": "Closed"}, headers=headers(api))
    assert closed.status_code == 200
    assert closed.json["vulnerability"]["status"] == "Closed"
    assert closed.json["vulnerability"]["resolution_date"] == resolution_date


@pytest.mark.parametrize("current,requested", [
    ("Open", "In Progress"),
    ("Open", "Closed"),
    ("Under Investigation", "Open"),
    ("In Progress", "Closed"),
    ("Resolved", "In Progress"),
])
def test_invalid_status_transitions_return_409(api, current, requested):
    vulnerability_id = seed(api, status=current)
    response = api["client"].put(
        f"/vulnerabilities/{vulnerability_id}", json={"status": requested},
        headers=headers(api),
    )
    assert response.status_code == 409
    assert stored(api, vulnerability_id)["status"] == current


def test_same_status_is_not_a_transition(api):
    vulnerability_id = seed(api, status="In Progress")
    response = api["client"].put(
        f"/vulnerabilities/{vulnerability_id}",
        json={"status": "In Progress", "description": "Patch scheduled."},
        headers=headers(api),
    )
    assert response.status_code == 200
    assert stored(api, vulnerability_id)["description"] == "Patch scheduled."


def test_closed_vulnerability_is_read_only(api):
    vulnerability_id = seed(api, status="Closed")
    response = api["client"].put(
        f"/vulnerabilities/{vulnerability_id}", json={"description": "Changed"},
        headers=headers(api),
    )
    assert response.status_code == 409
    assert stored(api, vulnerability_id)["description"] == "Fixture vulnerability"


def test_explicit_resolution_date_is_normalized(api):
    vulnerability_id = seed(api, status="In Progress", created_at="2026-01-10T08:00:00.000Z")
    response = api["client"].put(
        f"/vulnerabilities/{vulnerability_id}",
        json={"status": "Resolved", "resolution_date": "2026-01-12T10:30:00+02:00"},
        headers=headers(api),
    )
    assert response.status_code == 200, response.get_json()
    assert stored(api, vulnerability_id)["resolution_date"] == "2026-01-12T08:30:00.000Z"


def test_resolution_date_requires_resolved_status(api):
    vulnerability_id = seed(api, status="In Progress")
    response = api["client"].put(
        f"/vulnerabilities/{vulnerability_id}",
        json={"resolution_date": "2026-01-12"}, headers=headers(api),
    )
    assert response.status_code == 409
    assert stored(api, vulnerability_id)["resolution_date"] is None


@pytest.mark.parametrize("resolution_date", [
    "yesterday",
    "2026-13-01",
    "",
    12,
    (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
    "2026-01-09",
])
def test_invalid_resolution_dates_return_400(api, resolution_date):
    vulnerability_id = seed(api, status="Resolved", created_at="2026-01-10T08:00:00.000Z")
    response = api["client"].put(
        f"/vulnerabilities/{vulnerability_id}",
        json={"resolution_date": resolution_date}, headers=headers(api),
    )
    assert response.status_code == 400


@pytest.mark.parametrize("payload", [
    {},
    {"title": "Renamed"},
    {"cve_identifier": "CVE-2020-0001"},
    {"affected_asset_id": 2},
    {"discovery_source": "Bug Bounty"},
    {"status": "Reopened"},
    {"description": "   "},
    {"cvss_score": "high"},
])
def test_update_rejects_invalid_payload(api, payload):
    vulnerability_id = seed(api)
    response = api["client"].put(
        f"/vulnerabilities/{vulnerability_id}", json=payload, headers=headers(api)
    )
    assert response.status_code == 400
    assert stored(api, vulnerability_id)["status"] == "Open"


def test_update_missing_vulnerability_returns_404(api):
    response = api["client"].put(
        "/vulnerabilities/999", json={"status": "Under Investigation"},
        headers=headers(api),
    )
    assert response.status_code == 404


# 5. GET /vulnerabilities/search

@pytest.mark.parametrize("query,expected_ids", [
    ("cve_identifier=CVE-2024-3094", [1]),
    ("cve_identifier=cve-2023", [3, 2]),
    ("severity=High", [2]),
    ("affected_asset_id=2", [3, 2]),
    ("status=In+Progress", [3]),
    ("severity=Medium&affected_asset_id=2&status=In+Progress", [3]),
    ("severity=Critical&affected_asset_id=2", []),
])
def test_search_by_each_field_and_combinations(api, query, expected_ids):
    seed(api)
    seed(api, cve="CVE-2023-4863", score=8.8, severity="High", asset_id=2)
    seed(api, cve="CVE-2023-0001", score=5.3, severity="Medium", asset_id=2,
         status="In Progress")
    response = api["client"].get(
        "/vulnerabilities/search?" + query, headers=headers(api, "AUDITOR")
    )
    assert response.status_code == 200
    assert [item["id"] for item in response.json["vulnerabilities"]] == expected_ids
    assert response.json["count"] == len(expected_ids)


@pytest.mark.parametrize("query", [
    "",
    "unknown=abc",
    "severity=Extreme",
    "status=Reopened",
    "affected_asset_id=abc",
    "affected_asset_id=0",
    "cve_identifier=",
    "cve_identifier=%25",
    "cve_identifier=%27%20OR%201%3D1--",
    "severity=High&severity=Low",
])
def test_search_invalid_filters_return_400(api, query):
    response = api["client"].get(
        "/vulnerabilities/search" + ("?" + query if query else ""),
        headers=headers(api),
    )
    assert response.status_code == 400


# 6. DELETE /vulnerabilities/<id>

def test_delete_removes_record(api):
    vulnerability_id = seed(api)
    response = api["client"].delete(
        f"/vulnerabilities/{vulnerability_id}", headers=headers(api)
    )
    assert response.status_code == 200
    assert response.json["deleted_id"] == vulnerability_id
    assert stored(api, vulnerability_id) is None


def test_delete_missing_returns_404(api):
    response = api["client"].delete("/vulnerabilities/999", headers=headers(api))
    assert response.status_code == 404


# Authentication and authorization on ALL six routes

ALL_ROUTES = [
    ("post", "/vulnerabilities", sample_vulnerability()),
    ("get", "/vulnerabilities", None),
    ("get", "/vulnerabilities/1", None),
    ("get", "/vulnerabilities/search?severity=High", None),
    ("put", "/vulnerabilities/1", {"status": "Under Investigation"}),
    ("delete", "/vulnerabilities/1", None),
]


@pytest.mark.parametrize("method,path,body", ALL_ROUTES)
def test_all_endpoints_require_authentication(api, method, path, body):
    response = getattr(api["client"], method)(path, json=body)
    assert response.status_code == 401


@pytest.mark.parametrize("method,path,body", ALL_ROUTES)
def test_employee_has_no_vulnerability_access(api, method, path, body):
    seed(api)
    response = getattr(api["client"], method)(
        path, json=body, headers=headers(api, "EMPLOYEE")
    )
    assert response.status_code == 403
    assert stored(api, 1)["status"] == "Open"


@pytest.mark.parametrize("role,method,path,body", [
    ("AUDITOR", "post", "/vulnerabilities", sample_vulnerability(affected_asset_id=2)),
    ("AUDITOR", "put", "/vulnerabilities/1", {"status": "Under Investigation"}),
    ("AUDITOR", "delete", "/vulnerabilities/1", None),
    ("ANALYST", "post", "/vulnerabilities", sample_vulnerability(affected_asset_id=2)),
    ("ANALYST", "delete", "/vulnerabilities/1", None),
])
def test_restricted_roles_cannot_modify(api, role, method, path, body):
    seed(api)
    response = getattr(api["client"], method)(path, json=body, headers=headers(api, role))
    assert response.status_code == 403
    assert count(api) == 1
    assert stored(api, 1)["status"] == "Open"


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST", "AUDITOR"])
@pytest.mark.parametrize("path", [
    "/vulnerabilities", "/vulnerabilities/1", "/vulnerabilities/search?severity=Critical",
])
def test_read_roles_are_allowed(api, role, path):
    seed(api)
    response = api["client"].get(path, headers=headers(api, role))
    assert response.status_code == 200
