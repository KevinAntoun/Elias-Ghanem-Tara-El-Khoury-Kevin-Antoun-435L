"""One SQLite connection per Flask application context."""

import sqlite3
from flask import g
from shared.config import database_path


def get_db() -> sqlite3.Connection:
    """Get a request-scoped SQLite connection with foreign keys enabled.

    When adding write APIs, commit on success and roll back on failure.
    Always use parameterized queries (``?`` placeholders).
    """
    if "db" not in g:
        connection = sqlite3.connect(str(database_path()), timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        g.db = connection
    return g.db


def close_db(_error=None) -> None:
    """Close the request's connection, if one was opened."""
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()
