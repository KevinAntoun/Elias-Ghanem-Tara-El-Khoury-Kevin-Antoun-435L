"""Patch 3 regression tests: admin bootstrap, protected references, RBAC changes."""

import sqlite3
from urllib.parse import urlsplit

import pytest
from werkzeug.security import check_password_hash

from scripts.bootstrap_admin import create_initial_admin
from shared.app_factory import create_app
from shared.reference_client import lookup_user, ReferenceUnavailable
from services.users.routes import bp as users_bp
from services.assets.routes import bp as assets_bp


SECRET = "reference-test-secret-" + "p" * 48


def test_bootstrap_admin_once(db_path):
    user_id = create_initial_admin(
        full_name="Initial Admin", username="initial_admin", email="initial@example.test",
        password="StrongPassword123", path=db_path,
    )
    with sqlite3.connect(db_path) as db:
        row = db.execute("SELECT role, password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
        assert row[0] == "ADMIN"
        assert check_password_hash(row[1], "StrongPassword123")
        assert db.execute("SELECT action FROM logs WHERE user_id = ?", (user_id,)).fetchone()[0] == "ADMIN_BOOTSTRAPPED"
    with pytest.raises(ValueError, match="already exists"):
        create_initial_admin(full_name="Another Admin", username="anotheradmin",
                             email="another@example.test", password="StrongPassword123", path=db_path)


def test_admin_changes_role_and_role_effect_is_immediate(users_client, accounts, auth_headers, db):
    user_id = accounts["EMPLOYEE"]
    changed = users_client.put(f"/users/{user_id}", json={"role": "ANALYST"},
                               headers=auth_headers["ADMIN"])
    assert changed.status_code == 200, changed.get_json()
    assert changed.json["user"]["role"] == "ANALYST"
    assert db.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()[0] == "ANALYST"
    bad = users_client.put(f"/users/{user_id}", json={"role": "ADMIN"},
                           headers=auth_headers["ANALYST"])
    assert bad.status_code == 403
    bad_type = users_client.put(f"/users/{user_id}", json={"role": []},
                               headers=auth_headers["ADMIN"])
    assert bad_type.status_code == 400


def test_last_active_admin_is_protected(users_client, db, accounts, auth_headers):
    admin_id = accounts["ADMIN"]
    for field, value in (("role", "EMPLOYEE"), ("account_status", "Suspended")):
        response = users_client.put(f"/users/{admin_id}", json={field: value},
                                    headers=auth_headers["ADMIN"])
        assert response.status_code == 409
    assert tuple(db.execute("SELECT role,account_status FROM users WHERE id=?", (admin_id,)).fetchone()) == ("ADMIN", "Active")


def test_reference_endpoints_reject_forged_service(db_path, accounts, monkeypatch):
    monkeypatch.setenv("REFERENCE_TOKEN_USERS_ASSETS", SECRET)
    app = create_app("users", [users_bp]); app.config.update(TESTING=True)
    client = app.test_client()
    url = f"/internal/references/users/{accounts['EMPLOYEE']}"
    assert client.get(url).status_code == 401
    assert client.get(url, headers={"X-Service-Name": "assets"}).status_code == 401
    response = client.get(url, headers={
        "X-Service-Name": "assets", "Authorization": f"Service {SECRET}",
    })
    assert response.status_code == 200
    assert response.json["user"]["role"] == "EMPLOYEE"
    assert "password_hash" not in response.json["user"]
    assert client.get("/internal/references/users/999999", headers={
        "X-Service-Name": "assets", "Authorization": f"Service {SECRET}",
    }).status_code == 404


def test_reference_client_calls_real_owner_route(db_path, accounts, monkeypatch):
    monkeypatch.setenv("REFERENCE_TOKEN_USERS_ASSETS", SECRET)
    owner = create_app("users", [users_bp]); owner.config.update(TESTING=True)
    caller = create_app("assets", [assets_bp]); caller.config.update(TESTING=True)

    class Result:
        def __init__(self, response):
            self.status_code = response.status_code
            self.data = response.get_json()
        def raise_for_status(self):
            if self.status_code >= 400:
                raise ValueError("upstream")
        def json(self):
            return self.data

    def mocked_get(url, headers, timeout):
        path = urlsplit(url).path
        return Result(owner.test_client().get(path, headers=headers))

    monkeypatch.setattr("shared.reference_client.requests.get", mocked_get)
    with caller.app_context():
        user = lookup_user(accounts["EMPLOYEE"])
        assert user["account_status"] == "Active"
        assert lookup_user(999999) is None


def test_reference_client_fails_closed_without_credential(db_path, monkeypatch):
    monkeypatch.delenv("REFERENCE_TOKEN_USERS_ASSETS", raising=False)
    app = create_app("assets", [assets_bp]); app.config.update(TESTING=True)
    with app.app_context():
        with pytest.raises(ReferenceUnavailable):
            lookup_user(1)


def test_assets_create_uses_authenticated_users_reference(
    db_path, accounts, auth_headers, monkeypatch
):
    monkeypatch.setenv("REFERENCE_TOKEN_USERS_ASSETS", SECRET)
    user_app = create_app("users", [users_bp]); user_app.config.update(TESTING=True)
    asset_app = create_app("assets", [assets_bp]); asset_app.config.update(
        TESTING=True, REFERENCE_HTTP_IN_TESTS=True
    )

    class Response:
        def __init__(self, result):
            self.status_code = result.status_code
            self._body = result.get_json()
        def raise_for_status(self):
            if self.status_code >= 400:
                raise ValueError("Invalid upstream status")
        def json(self):
            return self._body

    def fake_http_get(url, headers, timeout):
        assert timeout == 2
        assert headers["X-Service-Name"] == "assets"
        assert headers["Authorization"] == f"Service {SECRET}"
        path = urlsplit(url).path
        return Response(user_app.test_client().get(path, headers=headers))

    monkeypatch.setattr("shared.reference_client.requests.get", fake_http_get)
    response = asset_app.test_client().post("/assets", json={
        "name": "Reference-tested server", "asset_type": "Server",
        "owner_id": accounts["EMPLOYEE"], "criticality": "High",
    }, headers=auth_headers["ADMIN"])
    assert response.status_code == 201, response.get_json()


def test_missing_upstream_credential_returns_503_not_false_validation(
    db_path, accounts, auth_headers, monkeypatch
):
    monkeypatch.delenv("REFERENCE_TOKEN_USERS_ASSETS", raising=False)
    asset_app = create_app("assets", [assets_bp]); asset_app.config.update(
        TESTING=True, REFERENCE_HTTP_IN_TESTS=True
    )
    response = asset_app.test_client().post("/assets", json={
        "name": "Unvalidated server", "asset_type": "Server",
        "owner_id": accounts["EMPLOYEE"], "criticality": "High",
    }, headers=auth_headers["ADMIN"])
    assert response.status_code == 503
    assert response.get_json()["status"] == "error"
