
"""Tests for shared JWT authentication and authorization."""

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from flask import Flask, jsonify

import shared.auth as auth


TEST_SECRET = "test-only-secret-" + "a" * 48


@pytest.fixture
def setup_auth(monkeypatch):
    """Create test users and a protected Flask endpoint."""
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row

    schema_path = (
        Path(__file__).resolve().parents[1]
        / "database"
        / "schema.sql"
    )
    db.executescript(schema_path.read_text(encoding="utf-8"))

    db.executemany(
        """
        INSERT INTO users (
            full_name, username, email,
            password_hash, role, account_status
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (
                "Test Admin", "admin_test",
                "admin_test@example.com",
                "unused-test-hash", "ADMIN", "Active"
            ),
            (
                "Test Employee", "employee_test",
                "employee_test@example.com",
                "unused-test-hash", "EMPLOYEE", "Active"
            ),
        ],
    )
    db.commit()

    monkeypatch.setattr(auth, "get_db", lambda: db)

    app = Flask(__name__)

    @app.get("/admin-only")
    @auth.require_roles("ADMIN")
    def admin_only():
        return jsonify({
            "user_id": auth.current_user()["id"],
            "message": "Access granted"
        }), 200

    yield app.test_client(), db

    db.close()


def test_admin_can_access(setup_auth):
    client, _ = setup_auth
    token = auth.create_access_token(1)

    response = client.get(
        "/admin-only",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json["user_id"] == 1


def test_employee_cannot_access(setup_auth):
    client, _ = setup_auth
    token = auth.create_access_token(2)

    response = client.get(
        "/admin-only",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


def test_missing_token(setup_auth):
    client, _ = setup_auth

    response = client.get(
        "/admin-only",
        headers={"X-Role": "ADMIN"},
    )

    assert response.status_code == 401


def test_invalid_token(setup_auth):
    client, _ = setup_auth

    response = client.get(
        "/admin-only",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401


def test_suspended_user_cannot_access(setup_auth):
    client, db = setup_auth
    token = auth.create_access_token(1)

    db.execute(
        "UPDATE users SET account_status = ? WHERE id = ?",
        ("Suspended", 1),
    )
    db.commit()

    response = client.get(
        "/admin-only",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_role_change_takes_effect(setup_auth):
    client, db = setup_auth
    token = auth.create_access_token(1)

    db.execute(
        "UPDATE users SET role = ? WHERE id = ?",
        ("EMPLOYEE", 1),
    )
    db.commit()

    response = client.get(
        "/admin-only",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


def test_expired_token(setup_auth):
    client, _ = setup_auth
    past = datetime.now(timezone.utc) - timedelta(hours=2)

    token = jwt.encode(
        {
            "sub": "1",
            "iss": auth.JWT_ISSUER,
            "iat": past,
            "nbf": past,
            "exp": past + timedelta(hours=1),
            "type": "access",
        },
        TEST_SECRET,
        algorithm="HS256",
    )

    response = client.get(
        "/admin-only",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
