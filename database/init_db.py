"""Initialize the team's local SQLite file from starter SQL schema."""

import sqlite3
from pathlib import Path

from shared.config import PROJECT_ROOT, database_path


def initialize_db(path: Path | None = None) -> Path:
    """Create the local database and apply idempotent CREATE TABLE statements."""
    target = path or database_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    sql = (PROJECT_ROOT / "database" / "schema.sql").read_text(encoding="utf-8")
    with sqlite3.connect(str(target)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(sql)
    return target


if __name__ == "__main__":
    print(f"Initialized starter SQLite schema: {initialize_db()}")
    print("Review and extend the schema with your teammates before implementation.")
