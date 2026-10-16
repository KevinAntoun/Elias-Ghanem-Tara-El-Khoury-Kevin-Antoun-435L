"""Schema creation smoke test using a temporary database, not student data."""

import sqlite3
from database.init_db import initialize_db


def test_schema_contains_ten_starter_tables(tmp_path):
    filename = initialize_db(tmp_path / "sample.db")
    with sqlite3.connect(filename) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        required = {
            "users", "assets", "incidents", "investigation_notes", "threats",
            "logs", "vulnerabilities", "notifications", "playbooks", "response_actions",
        }
        assert required.issubset(tables)
        # Reapplying the CREATE TABLE statements should be safe.
        initialize_db(filename)
