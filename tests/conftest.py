"""Shared isolated SQLite fixtures for Tara's three Sprint 1 services.

Copy into repository tests/ alongside the three test_*.py files.
"""
import sqlite3
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

from shared import database
from services.users.app import app as users_app
from services.assets.app import app as assets_app
from services.incidents.app import app as incidents_app


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    """Initialize the real repository schema in a disposable SQLite database."""
    path = tmp_path / "security_test.db"
    schema = Path(__file__).resolve().parents[1] / "database" / "schema.sql"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(schema.read_text(encoding="utf-8"))
    conn.close()
    monkeypatch.setattr(database, "database_path", lambda: path)
    monkeypatch.setenv("JWT_SECRET", "test-only-not-production-key-0123456789abcdef")
    return path


@pytest.fixture
def db(db_path):
    """Direct fixture access for setup and post-request persistence assertions."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    yield conn
    conn.close()


@pytest.fixture
def users_client(db_path):
    users_app.config.update(TESTING=True)
    return users_app.test_client()


@pytest.fixture
def assets_client(db_path):
    assets_app.config.update(TESTING=True)
    return assets_app.test_client()


@pytest.fixture
def incidents_client(db_path):
    incidents_app.config.update(TESTING=True)
    return incidents_app.test_client()


@pytest.fixture
def accounts(db):
    """Create real hashed-password accounts in all four roles."""
    ids = {}
    for role in ("ADMIN", "EMPLOYEE", "ANALYST", "AUDITOR"):
        name = role.lower()
        cur = db.execute(
            """INSERT INTO users
               (full_name, username, email, password_hash, department, role, account_status)
               VALUES (?, ?, ?, ?, ?, ?, 'Active')""",
            (name.title(), name, f"{name}@example.test",
             generate_password_hash("ValidPass123"), "IT", role),
        )
        ids[role] = cur.lastrowid
    db.commit()
    return ids


@pytest.fixture
def auth_headers(accounts):
    """Generate signed JWTs with the actual shared auth interface."""
    from shared.auth import create_access_token
    return {
        role: {"Authorization": f"Bearer {create_access_token(user_id)}"}
        for role, user_id in accounts.items()
    }


@pytest.fixture
def asset_id(db, accounts):
    cur = db.execute(
        """INSERT INTO assets
           (name, asset_type, owner_id, criticality, status, ip_address, department)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        ("Fixture Server", "Server", accounts["EMPLOYEE"], "High", "Active",
         "192.168.10.10", "IT"),
    )
    db.commit()
    return cur.lastrowid


@pytest.fixture
def incident_id(db, accounts, asset_id):
    cur = db.execute(
        """INSERT INTO incidents
           (title, description, category, severity, reporter_id,
            affected_asset_id, assigned_analyst_id, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        ("Test incident", "Investigation test", "Malware", "High",
         accounts["EMPLOYEE"], asset_id, accounts["ANALYST"], "Open"),
    )
    db.commit()
    return cur.lastrowid
