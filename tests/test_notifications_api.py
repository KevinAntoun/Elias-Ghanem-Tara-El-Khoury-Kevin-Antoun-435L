"""Flask tests for all six Notification and Alert Management routes (Elias Ghanem).

Run from the repository root:
    python -m pytest tests/test_notifications_api.py -v

The test database is in memory. These tests do not touch the team's SQLite file.
"""

import re
import sqlite3
from pathlib import Path

import pytest

import services.notifications.routes as notification_routes
import shared.auth as auth
from shared.app_factory import create_app


TEST_JWT_SECRET = "only-for-test-use-" + "n" * 48
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")

ADMIN_ID, ANALYST_ID, AUDITOR_ID, EMPLOYEE_ID, OTHER_EMPLOYEE_ID, INACTIVE_ID = range(1, 7)


@pytest.fixture
def api(monkeypatch):
    """Provide real Flask HTTP requests backed by a private SQLite database."""
    monkeypatch.setenv("JWT_SECRET", TEST_JWT_SECRET)

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    schema_path = Path(__file__).resolve().parents[1] / "database" / "schema.sql"
    db.executescript(schema_path.read_text(encoding="utf-8"))

    for name, role, account_status in (
        ("notif_admin", "ADMIN", "Active"),
        ("notif_analyst", "ANALYST", "Active"),
        ("notif_auditor", "AUDITOR", "Active"),
        ("notif_employee", "EMPLOYEE", "Active"),
        ("notif_employee2", "EMPLOYEE", "Active"),
        ("notif_inactive", "EMPLOYEE", "Inactive"),
    ):
        db.execute(
            """INSERT INTO users
               (full_name, username, email, password_hash, role, account_status)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, name, f"{name}@example.com", "unused-test-hash", role, account_status),
        )
    db.commit()

    monkeypatch.setattr(auth, "get_db", lambda: db)
    monkeypatch.setattr(notification_routes, "get_db", lambda: db)

    app = create_app("notifications", [notification_routes.bp])
    app.config["TESTING"] = True
    tokens = {
        "ADMIN": auth.create_access_token(ADMIN_ID),
        "ANALYST": auth.create_access_token(ANALYST_ID),
        "AUDITOR": auth.create_access_token(AUDITOR_ID),
        "EMPLOYEE": auth.create_access_token(EMPLOYEE_ID),
        "INACTIVE": auth.create_access_token(INACTIVE_ID),
    }
    yield {"client": app.test_client(), "db": db, "tokens": tokens}
    db.close()


def headers(api, role="ADMIN"):
    """Return an Authorization header for a test user."""
    return {"Authorization": f"Bearer {api['tokens'][role]}"}


def sample_notification(**overrides):
    """Return a valid creation body, optionally overriding some fields."""
    data = {
        "user_id": ANALYST_ID,
        "title": "Incident INC-12 assigned to you",
        "message": "You have been assigned the phishing incident on the HR mailbox.",
        "notification_type": "Incident Assignment",
        "severity": "High",
    }
    data.update(overrides)
    return data


def seed(api, *, user_id=ANALYST_ID, notification_type="Security Alert",
         severity="Medium", status="Unread", read_at=None, created_at=None):
    """Insert a fixture directly so read/update/delete tests are independent."""
    columns = ["user_id", "title", "message", "notification_type", "severity",
               "status", "read_at"]
    values = [user_id, "Fixture", "Fixture notification", notification_type,
              severity, status, read_at]
    if created_at is not None:
        columns.append("created_at")
        values.append(created_at)
    cursor = api["db"].execute(
        f"INSERT INTO notifications ({', '.join(columns)}) "
        f"VALUES ({', '.join('?' for _ in columns)})",
        values,
    )
    api["db"].commit()
    return cursor.lastrowid


def stored(api, notification_id):
    return api["db"].execute(
        "SELECT * FROM notifications WHERE id = ?", (notification_id,)
    ).fetchone()


def count(api):
    return api["db"].execute("SELECT COUNT(*) FROM notifications").fetchone()[0]


def ids(response):
    return [item["id"] for item in response.json["notifications"]]


# 1. POST /notifications

def test_create_persists_and_returns_201(api):
    response = api["client"].post(
        "/notifications", json=sample_notification(), headers=headers(api)
    )
    assert response.status_code == 201, response.get_json()
    assert response.json["status"] == "success"
    body = response.json["notification"]
    assert body["id"] == 1
    assert body["user_id"] == ANALYST_ID
    assert body["status"] == "Unread"
    assert body["read_at"] is None
    assert TIMESTAMP.fullmatch(body["created_at"])
    assert response.headers["Location"] == "/notifications/1"
    row = stored(api, 1)
    assert row["notification_type"] == "Incident Assignment"
    assert row["severity"] == "High"
    assert row["status"] == "Unread"


@pytest.mark.parametrize("notification_type", notification_routes.NOTIFICATION_TYPES)
def test_create_accepts_every_notification_type(api, notification_type):
    response = api["client"].post(
        "/notifications",
        json=sample_notification(notification_type=notification_type),
        headers=headers(api),
    )
    assert response.status_code == 201
    assert response.json["notification"]["notification_type"] == notification_type


@pytest.mark.parametrize("severity", notification_routes.SEVERITIES)
def test_create_accepts_every_severity(api, severity):
    response = api["client"].post(
        "/notifications", json=sample_notification(severity=severity), headers=headers(api)
    )
    assert response.status_code == 201
    assert response.json["notification"]["severity"] == severity


def test_create_trims_text_fields(api):
    response = api["client"].post(
        "/notifications",
        json=sample_notification(title="  Alert  ", message=" Body ", severity=" Low "),
        headers=headers(api),
    )
    assert response.status_code == 201
    body = response.json["notification"]
    assert (body["title"], body["message"], body["severity"]) == ("Alert", "Body", "Low")


@pytest.mark.parametrize("field", sorted(notification_routes.CREATE_FIELDS))
def test_create_requires_every_field(api, field):
    data = sample_notification()
    del data[field]
    response = api["client"].post("/notifications", json=data, headers=headers(api))
    assert response.status_code == 400
    assert field in response.json["message"]
    assert count(api) == 0


@pytest.mark.parametrize("field, value", [
    ("status", "Read"),
    ("read_at", "2026-01-01T00:00:00.000Z"),
    ("created_at", "2026-01-01T00:00:00.000Z"),
    ("id", 99),
    ("priority", "urgent"),
])
def test_create_rejects_server_managed_and_unknown_fields(api, field, value):
    response = api["client"].post(
        "/notifications", json=sample_notification(**{field: value}), headers=headers(api)
    )
    assert response.status_code == 400
    assert field in response.json["message"]
    assert count(api) == 0


@pytest.mark.parametrize("overrides", [
    {"user_id": 0},
    {"user_id": -3},
    {"user_id": "2"},
    {"user_id": True},
    {"user_id": 2.0},
    {"user_id": None},
    {"title": ""},
    {"title": "   "},
    {"title": 5},
    {"title": "x" * 201},
    {"message": ""},
    {"message": None},
    {"message": "x" * 5001},
    {"notification_type": "Reminder"},
    {"notification_type": "security alert"},
    {"notification_type": 1},
    {"severity": "Extreme"},
    {"severity": "high"},
    {"severity": None},
])
def test_create_rejects_invalid_values(api, overrides):
    response = api["client"].post(
        "/notifications", json=sample_notification(**overrides), headers=headers(api)
    )
    assert response.status_code == 400
    assert response.json["status"] == "error"
    assert count(api) == 0


@pytest.mark.parametrize("user_id", [999, INACTIVE_ID])
def test_create_requires_existing_active_recipient(api, user_id):
    response = api["client"].post(
        "/notifications", json=sample_notification(user_id=user_id), headers=headers(api)
    )
    assert response.status_code == 400
    assert "active user" in response.json["message"]
    assert count(api) == 0


def test_create_requires_json_content_type(api):
    response = api["client"].post(
        "/notifications", data="user_id=2", headers=headers(api),
        content_type="application/x-www-form-urlencoded",
    )
    assert response.status_code == 400
    assert "application/json" in response.json["message"]


@pytest.mark.parametrize("raw", ["[1, 2]", "not json", '"text"'])
def test_create_requires_json_object(api, raw):
    response = api["client"].post(
        "/notifications", data=raw, headers=headers(api), content_type="application/json"
    )
    assert response.status_code == 400
    assert count(api) == 0


@pytest.mark.parametrize("role", ["ANALYST", "AUDITOR", "EMPLOYEE"])
def test_create_forbidden_for_non_admins(api, role):
    response = api["client"].post(
        "/notifications", json=sample_notification(), headers=headers(api, role)
    )
    assert response.status_code == 403
    assert count(api) == 0


def test_create_database_error_returns_500(api):
    api["db"].execute("DROP TABLE notifications")
    response = api["client"].post(
        "/notifications", json=sample_notification(), headers=headers(api)
    )
    assert response.status_code == 500
    assert response.json["message"] == "Unable to create notification."


# 2. GET /notifications/user/<user_id>

def test_user_history_newest_first(api):
    old = seed(api, created_at="2026-01-01T08:00:00.000Z")
    new = seed(api, created_at="2026-03-01T08:00:00.000Z")
    middle = seed(api, created_at="2026-02-01T08:00:00.000Z")
    seed(api, user_id=EMPLOYEE_ID)
    response = api["client"].get(f"/notifications/user/{ANALYST_ID}", headers=headers(api))
    assert response.status_code == 200
    assert response.json["status"] == "success"
    assert response.json["user_id"] == ANALYST_ID
    assert response.json["count"] == 3
    assert ids(response) == [new, middle, old]
    assert set(response.json["notifications"][0]) == set(notification_routes.NOTIFICATION_COLUMNS)


def test_user_history_same_timestamp_orders_by_id(api):
    first = seed(api, created_at="2026-01-01T08:00:00.000Z")
    second = seed(api, created_at="2026-01-01T08:00:00.000Z")
    response = api["client"].get(f"/notifications/user/{ANALYST_ID}", headers=headers(api))
    assert ids(response) == [second, first]


def test_user_history_empty_for_existing_user(api):
    response = api["client"].get(f"/notifications/user/{AUDITOR_ID}", headers=headers(api))
    assert response.status_code == 200
    assert response.json["count"] == 0
    assert response.json["notifications"] == []


def test_user_history_unknown_user_returns_404(api):
    response = api["client"].get("/notifications/user/999", headers=headers(api))
    assert response.status_code == 404
    assert response.json["message"] == "User not found."


@pytest.mark.parametrize("role", ["ADMIN", "AUDITOR"])
def test_user_history_admin_and_auditor_see_any_user(api, role):
    notification_id = seed(api, user_id=EMPLOYEE_ID)
    response = api["client"].get(
        f"/notifications/user/{EMPLOYEE_ID}", headers=headers(api, role)
    )
    assert response.status_code == 200
    assert ids(response) == [notification_id]


@pytest.mark.parametrize("role, own_id", [("ANALYST", ANALYST_ID), ("EMPLOYEE", EMPLOYEE_ID)])
def test_user_history_owner_sees_own(api, role, own_id):
    notification_id = seed(api, user_id=own_id)
    response = api["client"].get(f"/notifications/user/{own_id}", headers=headers(api, role))
    assert response.status_code == 200
    assert ids(response) == [notification_id]


@pytest.mark.parametrize("role, other_id", [
    ("ANALYST", EMPLOYEE_ID),
    ("EMPLOYEE", ANALYST_ID),
    ("EMPLOYEE", OTHER_EMPLOYEE_ID),
    ("EMPLOYEE", 999),
])
def test_user_history_owner_cannot_see_others(api, role, other_id):
    seed(api, user_id=ANALYST_ID)
    response = api["client"].get(f"/notifications/user/{other_id}", headers=headers(api, role))
    assert response.status_code == 403
    assert "notifications" not in response.json


def test_user_history_non_integer_id_returns_404(api):
    response = api["client"].get("/notifications/user/abc", headers=headers(api))
    assert response.status_code == 404


# 3. GET /notifications/<id>

def test_get_returns_details(api):
    notification_id = seed(api, notification_type="Threat Alert", severity="Critical")
    response = api["client"].get(f"/notifications/{notification_id}", headers=headers(api))
    assert response.status_code == 200
    body = response.json["notification"]
    assert body["id"] == notification_id
    assert body["notification_type"] == "Threat Alert"
    assert body["severity"] == "Critical"
    assert body["status"] == "Unread"
    assert body["read_at"] is None


def test_get_unknown_id_returns_404(api):
    response = api["client"].get("/notifications/999", headers=headers(api))
    assert response.status_code == 404
    assert response.json["message"] == "Notification not found."


@pytest.mark.parametrize("role", ["ADMIN", "AUDITOR"])
def test_get_admin_and_auditor_see_any(api, role):
    notification_id = seed(api, user_id=EMPLOYEE_ID)
    response = api["client"].get(f"/notifications/{notification_id}", headers=headers(api, role))
    assert response.status_code == 200


@pytest.mark.parametrize("role, own_id", [("ANALYST", ANALYST_ID), ("EMPLOYEE", EMPLOYEE_ID)])
def test_get_owner_sees_own(api, role, own_id):
    notification_id = seed(api, user_id=own_id)
    response = api["client"].get(f"/notifications/{notification_id}", headers=headers(api, role))
    assert response.status_code == 200
    assert response.json["notification"]["user_id"] == own_id


@pytest.mark.parametrize("role, other_id", [("ANALYST", EMPLOYEE_ID), ("EMPLOYEE", ANALYST_ID)])
def test_get_owner_cannot_see_others(api, role, other_id):
    notification_id = seed(api, user_id=other_id)
    response = api["client"].get(f"/notifications/{notification_id}", headers=headers(api, role))
    assert response.status_code == 403
    assert "notification" not in response.json


# 4. PUT /notifications/<id>/read

def test_mark_read_sets_status_and_read_at(api):
    notification_id = seed(api)
    response = api["client"].put(f"/notifications/{notification_id}/read", headers=headers(api))
    assert response.status_code == 200
    assert response.json["message"] == "Notification marked as read."
    body = response.json["notification"]
    assert body["status"] == "Read"
    assert TIMESTAMP.fullmatch(body["read_at"])
    row = stored(api, notification_id)
    assert row["status"] == "Read"
    assert row["read_at"] == body["read_at"]
    assert row["read_at"] >= row["created_at"]


def test_mark_read_is_idempotent_and_keeps_read_at(api):
    original = "2026-02-02T10:00:00.000Z"
    notification_id = seed(api, status="Read", read_at=original)
    response = api["client"].put(f"/notifications/{notification_id}/read", headers=headers(api))
    assert response.status_code == 200
    assert response.json["message"] == "Notification was already marked as read."
    assert response.json["notification"]["read_at"] == original
    assert stored(api, notification_id)["read_at"] == original


def test_mark_read_twice_keeps_first_read_at(api):
    notification_id = seed(api)
    first = api["client"].put(f"/notifications/{notification_id}/read", headers=headers(api))
    second = api["client"].put(f"/notifications/{notification_id}/read", headers=headers(api))
    assert second.status_code == 200
    assert second.json["notification"]["read_at"] == first.json["notification"]["read_at"]


def test_mark_read_unknown_id_returns_404(api):
    response = api["client"].put("/notifications/999/read", headers=headers(api))
    assert response.status_code == 404


def test_mark_read_only_changes_target(api):
    target = seed(api)
    other = seed(api)
    api["client"].put(f"/notifications/{target}/read", headers=headers(api))
    assert stored(api, other)["status"] == "Unread"
    assert stored(api, other)["read_at"] is None


@pytest.mark.parametrize("role, own_id", [("ANALYST", ANALYST_ID), ("EMPLOYEE", EMPLOYEE_ID)])
def test_mark_read_owner_can_mark_own(api, role, own_id):
    notification_id = seed(api, user_id=own_id)
    response = api["client"].put(
        f"/notifications/{notification_id}/read", headers=headers(api, role)
    )
    assert response.status_code == 200
    assert stored(api, notification_id)["status"] == "Read"


@pytest.mark.parametrize("role, other_id", [("ANALYST", EMPLOYEE_ID), ("EMPLOYEE", ANALYST_ID)])
def test_mark_read_owner_cannot_mark_others(api, role, other_id):
    notification_id = seed(api, user_id=other_id)
    response = api["client"].put(
        f"/notifications/{notification_id}/read", headers=headers(api, role)
    )
    assert response.status_code == 403
    assert stored(api, notification_id)["status"] == "Unread"


def test_mark_read_admin_can_mark_anyone(api):
    notification_id = seed(api, user_id=EMPLOYEE_ID)
    response = api["client"].put(f"/notifications/{notification_id}/read", headers=headers(api))
    assert response.status_code == 200


def test_mark_read_forbidden_for_auditor(api):
    notification_id = seed(api, user_id=AUDITOR_ID)
    response = api["client"].put(
        f"/notifications/{notification_id}/read", headers=headers(api, "AUDITOR")
    )
    assert response.status_code == 403
    assert stored(api, notification_id)["status"] == "Unread"


# 5. GET /notifications/search

@pytest.fixture
def search_data(api):
    """Notifications spread across users, types, severities and statuses."""
    return {
        "analyst_high": seed(api, user_id=ANALYST_ID, notification_type="Threat Alert",
                             severity="High", created_at="2026-01-01T00:00:00.000Z"),
        "analyst_read": seed(api, user_id=ANALYST_ID, notification_type="Security Alert",
                             severity="Low", status="Read",
                             read_at="2026-01-03T00:00:00.000Z",
                             created_at="2026-01-02T00:00:00.000Z"),
        "employee_high": seed(api, user_id=EMPLOYEE_ID, notification_type="Threat Alert",
                              severity="High", created_at="2026-01-03T00:00:00.000Z"),
        "employee_vuln": seed(api, user_id=EMPLOYEE_ID,
                              notification_type="Vulnerability Alert",
                              severity="Critical", created_at="2026-01-04T00:00:00.000Z"),
    }


def search(api, query, role="ADMIN"):
    return api["client"].get(f"/notifications/search?{query}", headers=headers(api, role))


def test_search_by_user_id(api, search_data):
    response = search(api, f"user_id={EMPLOYEE_ID}")
    assert response.status_code == 200
    assert response.json["count"] == 2
    assert ids(response) == [search_data["employee_vuln"], search_data["employee_high"]]


def test_search_by_type(api, search_data):
    response = search(api, "notification_type=Threat Alert")
    assert ids(response) == [search_data["employee_high"], search_data["analyst_high"]]


def test_search_by_severity(api, search_data):
    response = search(api, "severity=Critical")
    assert ids(response) == [search_data["employee_vuln"]]


def test_search_by_status(api, search_data):
    response = search(api, "status=Read")
    assert ids(response) == [search_data["analyst_read"]]


def test_search_combines_filters_with_and(api, search_data):
    response = search(api, f"notification_type=Threat Alert&severity=High&user_id={ANALYST_ID}")
    assert ids(response) == [search_data["analyst_high"]]


def test_search_no_results(api, search_data):
    response = search(api, "notification_type=Incident Assignment")
    assert response.status_code == 200
    assert response.json["count"] == 0
    assert response.json["notifications"] == []


def test_search_auditor_sees_all(api, search_data):
    response = search(api, "severity=High", role="AUDITOR")
    assert response.status_code == 200
    assert response.json["count"] == 2


def test_search_analyst_limited_to_own(api, search_data):
    response = search(api, "severity=High", role="ANALYST")
    assert response.status_code == 200
    assert ids(response) == [search_data["analyst_high"]]


def test_search_analyst_own_user_id(api, search_data):
    response = search(api, f"user_id={ANALYST_ID}", role="ANALYST")
    assert response.status_code == 200
    assert response.json["count"] == 2


def test_search_analyst_other_user_id_forbidden(api, search_data):
    response = search(api, f"user_id={EMPLOYEE_ID}", role="ANALYST")
    assert response.status_code == 403


def test_search_requires_a_filter(api):
    response = api["client"].get("/notifications/search", headers=headers(api))
    assert response.status_code == 400
    assert "At least one" in response.json["message"]


@pytest.mark.parametrize("query", [
    "title=Alert",
    "read_at=2026-01-01",
    "severity=High&id=1",
    "severity=High&severity=Low",
    "status=",
    "status=   ",
    "user_id=abc",
    "user_id=0",
    "user_id=-1",
    "notification_type=Reminder",
    "severity=Extreme",
    "severity=high",
    "status=Archived",
    "status=read",
])
def test_search_rejects_invalid_filters(api, query):
    response = search(api, query)
    assert response.status_code == 400
    assert response.json["status"] == "error"


def test_search_is_not_vulnerable_to_injection(api, search_data):
    response = search(api, "severity=High' OR '1'='1")
    assert response.status_code == 400
    assert count(api) == 4


def test_search_forbidden_for_employee(api, search_data):
    response = search(api, "severity=High", role="EMPLOYEE")
    assert response.status_code == 403


# 6. DELETE /notifications/<id>

def test_delete_removes_notification(api):
    notification_id = seed(api)
    keep = seed(api)
    response = api["client"].delete(f"/notifications/{notification_id}", headers=headers(api))
    assert response.status_code == 200
    assert response.json["status"] == "success"
    assert response.json["deleted_id"] == notification_id
    assert stored(api, notification_id) is None
    assert stored(api, keep) is not None


def test_delete_unknown_id_returns_404(api):
    response = api["client"].delete("/notifications/999", headers=headers(api))
    assert response.status_code == 404


def test_delete_twice_returns_404(api):
    notification_id = seed(api)
    api["client"].delete(f"/notifications/{notification_id}", headers=headers(api))
    response = api["client"].delete(f"/notifications/{notification_id}", headers=headers(api))
    assert response.status_code == 404


@pytest.mark.parametrize("role", ["ANALYST", "AUDITOR", "EMPLOYEE"])
def test_delete_forbidden_for_non_admins(api, role):
    notification_id = seed(api, user_id=ANALYST_ID)
    response = api["client"].delete(
        f"/notifications/{notification_id}", headers=headers(api, role)
    )
    assert response.status_code == 403
    assert stored(api, notification_id) is not None


# Authentication on every route

ROUTES = [
    ("post", "/notifications"),
    ("get", f"/notifications/user/{ANALYST_ID}"),
    ("get", "/notifications/1"),
    ("put", "/notifications/1/read"),
    ("get", "/notifications/search?severity=High"),
    ("delete", "/notifications/1"),
]


@pytest.mark.parametrize("method, path", ROUTES)
def test_every_route_requires_token(api, method, path):
    seed(api)
    response = getattr(api["client"], method)(path, json=sample_notification())
    assert response.status_code == 401
    assert response.json["status"] == "error"


@pytest.mark.parametrize("method, path", ROUTES)
def test_every_route_rejects_invalid_token(api, method, path):
    seed(api)
    response = getattr(api["client"], method)(
        path, json=sample_notification(), headers={"Authorization": "Bearer not-a-jwt"}
    )
    assert response.status_code == 401


@pytest.mark.parametrize("method, path", ROUTES)
def test_every_route_rejects_inactive_account(api, method, path):
    seed(api)
    response = getattr(api["client"], method)(
        path, json=sample_notification(), headers=headers(api, "INACTIVE")
    )
    assert response.status_code == 401


ROLE_MATRIX = {
    # (method, path): roles allowed by the endpoint itself.
    ("post", "/notifications"): {"ADMIN"},
    ("get", f"/notifications/user/{ANALYST_ID}"): {"ADMIN", "ANALYST", "EMPLOYEE", "AUDITOR"},
    ("get", "/notifications/1"): {"ADMIN", "ANALYST", "EMPLOYEE", "AUDITOR"},
    ("put", "/notifications/1/read"): {"ADMIN", "ANALYST", "EMPLOYEE"},
    ("get", "/notifications/search?severity=High"): {"ADMIN", "ANALYST", "AUDITOR"},
    ("delete", "/notifications/1"): {"ADMIN"},
}


@pytest.mark.parametrize("method, path", ROUTES)
@pytest.mark.parametrize("role", ["ADMIN", "ANALYST", "AUDITOR", "EMPLOYEE"])
def test_role_matrix(api, method, path, role):
    """Notification 1 belongs to the analyst, so only ownership blocks the employee."""
    seed(api, user_id=ANALYST_ID)
    response = getattr(api["client"], method)(
        path, json=sample_notification(), headers=headers(api, role)
    )
    allowed = role in ROLE_MATRIX[(method, path)]
    if not allowed or role == "EMPLOYEE":
        assert response.status_code == 403, (role, method, path)
    else:
        assert response.status_code in (200, 201), (role, method, path, response.json)
