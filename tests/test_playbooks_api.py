"""Flask tests for all six Security Playbook routes (Elias Ghanem).

Run from the repository root:
    python -m pytest tests/test_playbooks_api.py -v

The test database is in memory. These tests do not touch the team's SQLite file.
"""

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import services.playbooks.routes as playbook_routes
import shared.auth as auth
from shared.app_factory import create_app


TEST_JWT_SECRET = "only-for-test-use-" + "p" * 48


@pytest.fixture
def api(monkeypatch):
    """Provide real Flask HTTP requests backed by a private SQLite database."""
    monkeypatch.setenv("JWT_SECRET", TEST_JWT_SECRET)

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    schema_path = Path(__file__).resolve().parents[1] / "database" / "schema.sql"
    db.executescript(schema_path.read_text(encoding="utf-8"))

    for name, role, status in (
        ("pb_admin", "ADMIN", "Active"),
        ("pb_analyst", "ANALYST", "Active"),
        ("pb_auditor", "AUDITOR", "Active"),
        ("pb_employee", "EMPLOYEE", "Active"),
        ("pb_inactive_analyst", "ANALYST", "Inactive"),
    ):
        db.execute(
            """INSERT INTO users
               (full_name, username, email, password_hash, role, account_status)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, name, f"{name}@example.com", "unused-test-hash", role, status),
        )
    db.commit()

    monkeypatch.setattr(auth, "get_db", lambda: db)
    monkeypatch.setattr(playbook_routes, "get_db", lambda: db)

    app = create_app("playbooks", [playbook_routes.bp, playbook_routes.actions_bp])
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


def sample_playbook(**overrides):
    """Return a valid creation body, optionally overriding some fields."""
    data = {
        "name": "Ransomware Containment",
        "description": "Contain and eradicate a ransomware outbreak.",
        "incident_category": "Malware",
        "severity": "Critical",
    }
    data.update(overrides)
    return data


def seed(api, *, name="Phishing Response", steps=(1, 2, 3), statuses=None,
         created_at=None):
    """Insert a playbook with Pending actions directly; return (id, action ids)."""
    columns = ["name", "description", "incident_category", "severity", "created_by"]
    values = [name, "Fixture playbook", "Phishing", "High", 1]
    if created_at is not None:
        columns.append("created_at")
        values.append(created_at)
    playbook_id = api["db"].execute(
        f"INSERT INTO playbooks ({', '.join(columns)}) "
        f"VALUES ({', '.join('?' for _ in columns)})",
        values,
    ).lastrowid
    statuses = statuses or {}
    action_ids = []
    for step in steps:
        status = statuses.get(step, "Pending")
        action_ids.append(api["db"].execute(
            """INSERT INTO response_actions
               (playbook_id, description, step_number, status, completion_date)
               VALUES (?, ?, ?, ?, ?)""",
            (playbook_id, f"Step {step}", step, status,
             "2026-01-01T00:00:00.000Z" if status == "Completed" else None),
        ).lastrowid)
    api["db"].commit()
    return playbook_id, action_ids


def action_row(api, action_id):
    return api["db"].execute(
        "SELECT * FROM response_actions WHERE id = ?", (action_id,)
    ).fetchone()


def count(api, table="playbooks"):
    return api["db"].execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def put_status(api, action_id, body, role="ADMIN"):
    return api["client"].put(
        f"/actions/{action_id}/status", json=body, headers=headers(api, role)
    )


# 1. POST /playbooks

def test_create_persists_and_returns_201(api):
    response = api["client"].post("/playbooks", json=sample_playbook(), headers=headers(api))
    assert response.status_code == 201, response.get_json()
    body = response.json["playbook"]
    assert body["id"] == 1
    assert body["created_by"] == 1
    assert body["created_by_username"] == "pb_admin"
    assert body["created_at"].endswith("Z")
    assert body["action_count"] == 0
    assert body["actions"] == []
    assert response.headers["Location"] == "/playbooks/1"
    row = api["db"].execute("SELECT * FROM playbooks WHERE id = 1").fetchone()
    assert row["severity"] == "Critical"
    assert row["incident_category"] == "Malware"


def test_create_trims_text(api):
    response = api["client"].post(
        "/playbooks",
        json=sample_playbook(name="  DDoS Mitigation ", severity=" High "),
        headers=headers(api),
    )
    assert response.status_code == 201
    assert response.json["playbook"]["name"] == "DDoS Mitigation"
    assert response.json["playbook"]["severity"] == "High"


def test_create_with_initial_actions_orders_them(api):
    response = api["client"].post(
        "/playbooks",
        json=sample_playbook(actions=[
            {"description": "Eradicate", "step_number": 3},
            {"description": "Isolate hosts", "step_number": 1, "assigned_user_id": 2},
            {"description": "Collect evidence", "step_number": 2},
        ]),
        headers=headers(api),
    )
    assert response.status_code == 201, response.get_json()
    playbook = response.json["playbook"]
    assert playbook["action_count"] == 3
    assert [a["step_number"] for a in playbook["actions"]] == [1, 2, 3]
    assert all(a["status"] == "Pending" for a in playbook["actions"])
    assert playbook["actions"][0]["assigned_user"] == {
        "id": 2, "username": "pb_analyst", "role": "ANALYST",
    }


@pytest.mark.parametrize("actions", [
    [{"description": "A", "step_number": 1}, {"description": "B", "step_number": 1}],
    [{"description": "A", "step_number": 0}],
    [{"description": "A"}],
    [{"description": "A", "step_number": 1, "status": "Completed"}],
    [{"description": "A", "step_number": 1, "assigned_user_id": 3}],
    [{"description": "A", "step_number": 1, "assigned_user_id": 99}],
    ["not an object"],
    {"description": "A", "step_number": 1},
])
def test_create_rejects_invalid_initial_actions_atomically(api, actions):
    response = api["client"].post(
        "/playbooks", json=sample_playbook(actions=actions), headers=headers(api)
    )
    assert response.status_code == 400
    assert count(api) == 0
    assert count(api, "response_actions") == 0


@pytest.mark.parametrize("field", sorted(playbook_routes.PLAYBOOK_FIELDS))
def test_create_requires_every_field(api, field):
    data = sample_playbook()
    del data[field]
    response = api["client"].post("/playbooks", json=data, headers=headers(api))
    assert response.status_code == 400
    assert field in response.json["message"]
    assert count(api) == 0


@pytest.mark.parametrize("invalid", [
    {"name": ""},
    {"name": "   "},
    {"name": 42},
    {"name": "x" * 151},
    {"description": None},
    {"incident_category": ""},
    {"incident_category": "x" * 101},
    {"severity": "Extreme"},
    {"severity": "critical"},
    {"severity": 3},
    {"created_by": 2},
    {"created_at": "2026-01-01"},
    {"id": 5},
    {"unexpected": True},
])
def test_create_rejects_invalid_fields(api, invalid):
    response = api["client"].post(
        "/playbooks", json=sample_playbook(**invalid), headers=headers(api)
    )
    assert response.status_code == 400
    assert response.json["status"] == "error"
    assert count(api) == 0


@pytest.mark.parametrize("severity", sorted(playbook_routes.SEVERITIES))
def test_create_accepts_each_severity(api, severity):
    response = api["client"].post(
        "/playbooks", json=sample_playbook(severity=severity), headers=headers(api)
    )
    assert response.status_code == 201


@pytest.mark.parametrize("name", ["Ransomware Containment", "RANSOMWARE containment",
                                  "  ransomware containment  "])
def test_create_rejects_duplicate_name_case_insensitive(api, name):
    assert api["client"].post(
        "/playbooks", json=sample_playbook(), headers=headers(api)
    ).status_code == 201
    response = api["client"].post(
        "/playbooks", json=sample_playbook(name=name), headers=headers(api)
    )
    assert response.status_code == 409
    assert count(api) == 1


def test_create_requires_json_object(api):
    client = api["client"]
    assert client.post("/playbooks", data="name=x", headers=headers(api)).status_code == 400
    assert client.post("/playbooks", json=[sample_playbook()], headers=headers(api)).status_code == 400
    assert client.post(
        "/playbooks", data="{bad json", content_type="application/json", headers=headers(api)
    ).status_code == 400
    assert count(api) == 0


# 2. GET /playbooks

def test_list_newest_first_with_action_counts(api):
    seed(api, name="Phishing Response", steps=(1, 2, 3), statuses={1: "Completed"})
    seed(api, name="Insider Threat", steps=())
    response = api["client"].get("/playbooks", headers=headers(api))
    assert response.status_code == 200
    body = response.json
    assert body["status"] == "success"
    assert body["count"] == 2
    assert [p["name"] for p in body["playbooks"]] == ["Insider Threat", "Phishing Response"]
    assert body["playbooks"][0]["action_count"] == 0
    assert body["playbooks"][1]["action_count"] == 3
    assert body["playbooks"][1]["completed_count"] == 1
    assert "actions" not in body["playbooks"][0]


def test_list_empty_database(api):
    response = api["client"].get("/playbooks", headers=headers(api))
    assert response.status_code == 200
    assert response.json["count"] == 0
    assert response.json["playbooks"] == []


# 3. GET /playbooks/<id>

def test_get_returns_actions_ordered_by_step(api):
    playbook_id, _ = seed(api, steps=(3, 1, 2))
    response = api["client"].get(f"/playbooks/{playbook_id}", headers=headers(api, "AUDITOR"))
    assert response.status_code == 200
    playbook = response.json["playbook"]
    assert playbook["name"] == "Phishing Response"
    assert playbook["severity"] == "High"
    assert playbook["incident_category"] == "Phishing"
    assert [a["step_number"] for a in playbook["actions"]] == [1, 2, 3]
    assert set(playbook["actions"][0]) == {
        "id", "playbook_id", "description", "step_number", "status",
        "assigned_user_id", "assigned_user", "completion_date",
    }


def test_get_missing_playbook_returns_404(api):
    response = api["client"].get("/playbooks/999", headers=headers(api))
    assert response.status_code == 404
    assert response.json == {"status": "error", "message": "Playbook not found."}


# 4. POST /playbooks/<id>/actions

@pytest.mark.parametrize("role", ["ADMIN", "ANALYST"])
def test_add_action_starts_pending(api, role):
    playbook_id, _ = seed(api, steps=())
    response = api["client"].post(
        f"/playbooks/{playbook_id}/actions",
        json={"description": "  Reset credentials ", "step_number": 1, "assigned_user_id": 2},
        headers=headers(api, role),
    )
    assert response.status_code == 201, response.get_json()
    action = response.json["action"]
    assert action["status"] == "Pending"
    assert action["description"] == "Reset credentials"
    assert action["completion_date"] is None
    assert action["assigned_user_id"] == 2
    assert response.headers["Location"] == f"/playbooks/{playbook_id}"


def test_add_action_without_assignee(api):
    playbook_id, _ = seed(api, steps=(1,))
    response = api["client"].post(
        f"/playbooks/{playbook_id}/actions",
        json={"description": "Notify users", "step_number": 2, "assigned_user_id": None},
        headers=headers(api),
    )
    assert response.status_code == 201
    assert response.json["action"]["assigned_user"] is None


def test_add_duplicate_step_returns_409(api):
    playbook_id, _ = seed(api, steps=(1, 2))
    response = api["client"].post(
        f"/playbooks/{playbook_id}/actions",
        json={"description": "Again", "step_number": 2},
        headers=headers(api),
    )
    assert response.status_code == 409
    assert count(api, "response_actions") == 2


def test_same_step_allowed_in_another_playbook(api):
    seed(api, name="First", steps=(1,))
    other_id, _ = seed(api, name="Second", steps=())
    response = api["client"].post(
        f"/playbooks/{other_id}/actions",
        json={"description": "Step one", "step_number": 1},
        headers=headers(api),
    )
    assert response.status_code == 201


def test_cannot_insert_step_before_started_step(api):
    playbook_id, _ = seed(api, steps=(1, 3), statuses={1: "Completed", 3: "In Progress"})
    response = api["client"].post(
        f"/playbooks/{playbook_id}/actions",
        json={"description": "Late step", "step_number": 2},
        headers=headers(api),
    )
    assert response.status_code == 409
    response = api["client"].post(
        f"/playbooks/{playbook_id}/actions",
        json={"description": "Follow-up", "step_number": 4},
        headers=headers(api),
    )
    assert response.status_code == 201


@pytest.mark.parametrize("body", [
    {},
    {"description": "No step"},
    {"step_number": 1},
    {"description": "", "step_number": 1},
    {"description": "x" * 2001, "step_number": 1},
    {"description": "Bad", "step_number": 0},
    {"description": "Bad", "step_number": -1},
    {"description": "Bad", "step_number": 1.5},
    {"description": "Bad", "step_number": "1"},
    {"description": "Bad", "step_number": True},
    {"description": "Bad", "step_number": 1, "status": "Completed"},
    {"description": "Bad", "step_number": 1, "completion_date": "2026-01-01"},
    {"description": "Bad", "step_number": 1, "assigned_user_id": "2"},
    {"description": "Bad", "step_number": 1, "assigned_user_id": 99},
    {"description": "Bad", "step_number": 1, "assigned_user_id": 3},
    {"description": "Bad", "step_number": 1, "assigned_user_id": 4},
    {"description": "Bad", "step_number": 1, "assigned_user_id": 5},
])
def test_add_action_rejects_invalid_body(api, body):
    playbook_id, _ = seed(api, steps=())
    response = api["client"].post(
        f"/playbooks/{playbook_id}/actions", json=body, headers=headers(api)
    )
    assert response.status_code == 400
    assert count(api, "response_actions") == 0


def test_add_action_requires_json(api):
    playbook_id, _ = seed(api, steps=())
    response = api["client"].post(
        f"/playbooks/{playbook_id}/actions", data="x", headers=headers(api)
    )
    assert response.status_code == 400


def test_add_action_missing_playbook_returns_404(api):
    response = api["client"].post(
        "/playbooks/999/actions", json={"description": "x", "step_number": 1},
        headers=headers(api),
    )
    assert response.status_code == 404


# 5. PUT /actions/<id>/status

def test_full_workflow_in_step_order(api):
    playbook_id, (first, second) = seed(api, steps=(1, 2))
    assert put_status(api, first, {"status": "In Progress", "assigned_user_id": 2},
                      "ANALYST").status_code == 200
    response = put_status(api, first, {"status": "Completed"}, "ANALYST")
    assert response.status_code == 200, response.get_json()
    completed = response.json["action"]
    assert completed["status"] == "Completed"
    assert completed["completion_date"].endswith("Z")
    assert completed["assigned_user"]["username"] == "pb_analyst"

    assert put_status(api, second, {"status": "In Progress"}).status_code == 200
    assert put_status(api, second, {"status": "Completed"}).status_code == 200
    playbook = api["client"].get(f"/playbooks/{playbook_id}", headers=headers(api)).json
    assert playbook["playbook"]["completed_count"] == 2


def test_completion_date_format_matches_schema(api):
    _, (first,) = seed(api, steps=(1,), statuses={1: "In Progress"})
    put_status(api, first, {"status": "Completed"})
    value = action_row(api, first)["completion_date"]
    assert datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    assert len(value) == 24


@pytest.mark.parametrize("current,requested", [
    ("Pending", "Completed"),
    ("In Progress", "Pending"),
])
def test_invalid_status_transitions_return_409(api, current, requested):
    _, (first,) = seed(api, steps=(1,), statuses={1: current})
    response = put_status(api, first, {"status": requested})
    assert response.status_code == 409
    assert action_row(api, first)["status"] == current


@pytest.mark.parametrize("requested,earlier", [
    ("In Progress", {}),
    ("In Progress", {1: "In Progress"}),
])
def test_cannot_start_before_earlier_steps_complete(api, requested, earlier):
    _, (_, second) = seed(api, steps=(1, 2), statuses=earlier)
    response = put_status(api, second, {"status": requested})
    assert response.status_code == 409
    assert "Earlier step(s) 1" in response.json["message"]
    assert action_row(api, second)["status"] == "Pending"


def test_cannot_complete_while_earlier_step_reopened(api):
    # Step 2 was started, then step 1 is somehow not finished (e.g. imported data).
    _, (_, second) = seed(api, steps=(1, 2), statuses={2: "In Progress"})
    response = put_status(api, second, {"status": "Completed"})
    assert response.status_code == 409
    assert action_row(api, second)["completion_date"] is None


def test_ordering_ignores_other_playbooks(api):
    seed(api, name="Other", steps=(1,))
    _, (first,) = seed(api, name="Mine", steps=(5,))
    assert put_status(api, first, {"status": "In Progress"}).status_code == 200


def test_ordering_uses_step_numbers_with_gaps(api):
    _, (low, high) = seed(api, steps=(10, 20), statuses={10: "Completed"})
    assert put_status(api, high, {"status": "In Progress"}).status_code == 200
    assert action_row(api, low)["status"] == "Completed"


def test_same_status_is_not_a_transition(api):
    _, (_, second) = seed(api, steps=(1, 2))
    response = put_status(api, second, {"status": "Pending", "assigned_user_id": 1})
    assert response.status_code == 200
    assert action_row(api, second)["assigned_user_id"] == 1


def test_completed_action_is_read_only(api):
    _, (first,) = seed(api, steps=(1,), statuses={1: "Completed"})
    for body in ({"status": "Completed"}, {"assigned_user_id": 2},
                 {"completion_date": "2026-01-02"}, {"status": "Pending"}):
        response = put_status(api, first, body)
        assert response.status_code == 409
    row = action_row(api, first)
    assert row["completion_date"] == "2026-01-01T00:00:00.000Z"
    assert row["assigned_user_id"] is None


def test_explicit_completion_date_is_normalized(api):
    _, (first,) = seed(api, steps=(1,), statuses={1: "In Progress"},
                       created_at="2026-01-01T00:00:00.000Z")
    response = put_status(
        api, first, {"status": "Completed", "completion_date": "2026-02-01T12:30:00+02:00"}
    )
    assert response.status_code == 200
    assert response.json["action"]["completion_date"] == "2026-02-01T10:30:00.000Z"


def test_completion_date_requires_completed_status(api):
    _, (first,) = seed(api, steps=(1,))
    response = put_status(api, first, {"completion_date": "2026-01-02"})
    assert response.status_code == 409
    response = put_status(api, first, {"status": "In Progress",
                                       "completion_date": "2026-01-02"})
    assert response.status_code == 409
    assert action_row(api, first)["status"] == "Pending"


@pytest.mark.parametrize("completion_date", [
    "not-a-date",
    "",
    17,
    (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
    "2025-12-31",
])
def test_invalid_completion_dates_return_400(api, completion_date):
    _, (first,) = seed(api, steps=(1,), statuses={1: "In Progress"},
                       created_at="2026-01-01T00:00:00.000Z")
    response = put_status(api, first, {"status": "Completed",
                                       "completion_date": completion_date})
    assert response.status_code == 400
    assert action_row(api, first)["status"] == "In Progress"


@pytest.mark.parametrize("user_id,expected", [
    (1, 200), (2, 200), (None, 200), (3, 400), (4, 400), (5, 400), (99, 400),
    ("2", 400), (0, 400), (True, 400),
])
def test_assignment_requires_active_admin_or_analyst(api, user_id, expected):
    _, (first,) = seed(api, steps=(1,))
    response = put_status(api, first, {"assigned_user_id": user_id})
    assert response.status_code == expected


@pytest.mark.parametrize("payload", [
    {},
    {"status": "Done"},
    {"status": 1},
    {"description": "Changed"},
    {"step_number": 9},
    {"playbook_id": 2},
])
def test_update_rejects_invalid_payload(api, payload):
    _, (first,) = seed(api, steps=(1,))
    response = put_status(api, first, payload)
    assert response.status_code == 400
    assert action_row(api, first)["status"] == "Pending"


def test_update_requires_json(api):
    _, (first,) = seed(api, steps=(1,))
    response = api["client"].put(f"/actions/{first}/status", data="x", headers=headers(api))
    assert response.status_code == 400


def test_update_missing_action_returns_404(api):
    response = put_status(api, 999, {"status": "In Progress"})
    assert response.status_code == 404


# 6. DELETE /playbooks/<id>

def test_delete_removes_playbook_and_actions(api):
    playbook_id, _ = seed(api, steps=(1, 2, 3), statuses={1: "Completed"})
    other_id, _ = seed(api, name="Keep me", steps=(1,))
    response = api["client"].delete(f"/playbooks/{playbook_id}", headers=headers(api))
    assert response.status_code == 200
    assert response.json["deleted_id"] == playbook_id
    assert response.json["deleted_actions"] == 3
    assert count(api) == 1
    assert count(api, "response_actions") == 1
    assert api["client"].get(f"/playbooks/{playbook_id}", headers=headers(api)).status_code == 404
    assert api["client"].get(f"/playbooks/{other_id}", headers=headers(api)).status_code == 200


def test_delete_is_atomic_on_database_error(api):
    playbook_id, _ = seed(api, steps=(1, 2))
    api["db"].execute(
        """CREATE TRIGGER block_playbook_delete BEFORE DELETE ON playbooks
           BEGIN SELECT RAISE(ABORT, 'blocked'); END"""
    )
    api["db"].commit()
    response = api["client"].delete(f"/playbooks/{playbook_id}", headers=headers(api))
    assert response.status_code == 500
    assert count(api) == 1
    assert count(api, "response_actions") == 2


def test_delete_missing_returns_404(api):
    response = api["client"].delete("/playbooks/999", headers=headers(api))
    assert response.status_code == 404


# Authentication and role-based access control

ALL_ROUTES = [
    ("post", "/playbooks", sample_playbook(name="New")),
    ("get", "/playbooks", None),
    ("get", "/playbooks/1", None),
    ("post", "/playbooks/1/actions", {"description": "x", "step_number": 9}),
    ("put", "/actions/1/status", {"status": "In Progress"}),
    ("delete", "/playbooks/1", None),
]


@pytest.mark.parametrize("method,path,body", ALL_ROUTES)
def test_all_endpoints_require_authentication(api, method, path, body):
    response = getattr(api["client"], method)(path, json=body)
    assert response.status_code == 401


@pytest.mark.parametrize("method,path,body", ALL_ROUTES)
def test_invalid_token_is_rejected(api, method, path, body):
    response = getattr(api["client"], method)(
        path, json=body, headers={"Authorization": "Bearer not-a-jwt"}
    )
    assert response.status_code == 401


@pytest.mark.parametrize("method,path,body", ALL_ROUTES)
def test_employee_has_no_playbook_access(api, method, path, body):
    seed(api, steps=(1,))
    response = getattr(api["client"], method)(
        path, json=body, headers=headers(api, "EMPLOYEE")
    )
    assert response.status_code == 403
    assert count(api) == 1
    assert count(api, "response_actions") == 1
    assert action_row(api, 1)["status"] == "Pending"


@pytest.mark.parametrize("role,method,path,body", [
    ("AUDITOR", "post", "/playbooks", sample_playbook(name="New")),
    ("AUDITOR", "post", "/playbooks/1/actions", {"description": "x", "step_number": 9}),
    ("AUDITOR", "put", "/actions/1/status", {"status": "In Progress"}),
    ("AUDITOR", "delete", "/playbooks/1", None),
    ("ANALYST", "post", "/playbooks", sample_playbook(name="New")),
    ("ANALYST", "delete", "/playbooks/1", None),
])
def test_restricted_roles_cannot_modify(api, role, method, path, body):
    seed(api, steps=(1,))
    response = getattr(api["client"], method)(path, json=body, headers=headers(api, role))
    assert response.status_code == 403
    assert count(api) == 1
    assert count(api, "response_actions") == 1
    assert action_row(api, 1)["status"] == "Pending"


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST", "AUDITOR"])
@pytest.mark.parametrize("path", ["/playbooks", "/playbooks/1"])
def test_read_roles_are_allowed(api, role, path):
    seed(api)
    response = api["client"].get(path, headers=headers(api, role))
    assert response.status_code == 200


def test_inactive_user_token_is_rejected(api):
    token = auth.create_access_token(5)
    response = api["client"].get("/playbooks", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_every_route_names_the_responsible_student():
    assert "Responsible student: Elias Ghanem." in playbook_routes.__doc__
    for view in (
        playbook_routes.create_playbook, playbook_routes.list_playbooks,
        playbook_routes.get_playbook, playbook_routes.add_action,
        playbook_routes.update_action_status, playbook_routes.delete_playbook,
    ):
        assert "Author: Elias Ghanem." in view.__doc__
