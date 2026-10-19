"""Local, one-time administrator provisioning without a public admin API.

Run from a trusted terminal after initializing the database:
    python -m scripts.bootstrap_admin

This command refuses to run if ANY ADMIN exists. It never accepts a password as
an argument and never prints secrets. Do not use on an untrusted shared machine.
"""

import getpass
import re
import sqlite3

from werkzeug.security import generate_password_hash
from shared.config import database_path


def create_initial_admin(*, full_name, username, email, password, department="Security", path=None):
    """Create the first admin with a password hash; reject repeated bootstraps."""
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        raise ValueError("Username must contain 3-30 letters, digits or underscores.")
    if not isinstance(email, str) or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Invalid email address.")
    if not isinstance(full_name, str) or not full_name.strip() or len(full_name.strip()) > 150:
        raise ValueError("Invalid full name.")
    if not isinstance(department, str) or not department.strip() or len(department) > 100:
        raise ValueError("Invalid department.")
    if (not isinstance(password, str) or not 8 <= len(password) <= 128
            or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password)
            or not re.search(r"\d", password)):
        raise ValueError("Password must be 8-128 characters with uppercase, lowercase and digit.")
    with sqlite3.connect(str(path or database_path())) as db:
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM users WHERE role='ADMIN' LIMIT 1").fetchone():
            raise ValueError("An administrator already exists; bootstrap is disabled.")
        try:
            cursor = db.execute(
                """INSERT INTO users
                   (full_name, username, email, password_hash, department, role, account_status)
                   VALUES (?, ?, ?, ?, ?, 'ADMIN', 'Active')""",
                (full_name.strip(), username.strip(), email.lower().strip(),
                 generate_password_hash(password), department.strip()),
            )
            db.execute(
                """INSERT INTO logs (user_id, action, description, severity, related_service)
                   VALUES (?, 'ADMIN_BOOTSTRAPPED', 'Initial admin provisioned locally', 'Warning', 'users')""",
                (cursor.lastrowid,),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username or email already exists.") from exc
        return cursor.lastrowid


def main():
    print("Provision initial administrator (local CLI only)")
    username = input("Username: ").strip()
    full_name = input("Full name: ").strip()
    email = input("Email: ").strip()
    department = input("Department [Security]: ").strip() or "Security"
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords do not match.")
    try:
        new_id = create_initial_admin(
            full_name=full_name, username=username, email=email,
            department=department, password=password,
        )
    except (ValueError, sqlite3.DatabaseError) as exc:
        raise SystemExit(f"Bootstrap failed: {exc}") from None
    print(f"Initial administrator provisioned (user ID {new_id}).")


if __name__ == "__main__":
    main()
