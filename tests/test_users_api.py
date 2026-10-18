"""Users API: all six endpoints, persistence, authentication and denials."""
import pytest
from werkzeug.security import check_password_hash


REGISTRATION = {
    "full_name": "New Employee", "username": "newemployee",
    "email": "newemployee@example.test", "password": "SecurePass123",
    "department": "IT",
}


def test_register_persists_hash_not_password(users_client, db):
    response = users_client.post("/users/register", json=REGISTRATION)
    assert response.status_code == 201
    user = response.get_json()["user"]
    assert user["role"] == "EMPLOYEE"
    assert "password_hash" not in user
    record = db.execute("SELECT * FROM users WHERE username = ?", ("newemployee",)).fetchone()
    assert record is not None
    assert record["password_hash"] != REGISTRATION["password"]
    assert check_password_hash(record["password_hash"], REGISTRATION["password"])


def test_register_duplicate_and_bad_input(users_client):
    assert users_client.post("/users/register", json=REGISTRATION).status_code == 201
    assert users_client.post("/users/register", json=REGISTRATION).status_code == 409
    assert users_client.post("/users/register", json={"username": "x"}).status_code == 400
    assert users_client.post("/users/register", json={**REGISTRATION, "password": "weak"}).status_code == 400
    assert users_client.post("/users/register", json={**REGISTRATION, "role": "ADMIN"}).status_code == 403


def test_login_valid_invalid_and_inactive(users_client, db, accounts):
    ok = users_client.post("/users/login", json={"username": "employee", "password": "ValidPass123"})
    assert ok.status_code == 200
    assert ok.get_json()["access_token"]
    assert users_client.post("/users/login", json={"username": "employee", "password": "wrong"}).status_code == 401
    assert users_client.post("/users/login", json={"username": "missing", "password": "ValidPass123"}).status_code == 401
    assert users_client.post("/users/login", json={"username": "employee"}).status_code == 400
    assert db.execute("SELECT last_login_at FROM users WHERE id = ?", (accounts["EMPLOYEE"],)).fetchone()[0]
    db.execute("UPDATE users SET account_status = 'Suspended' WHERE id = ?", (accounts["EMPLOYEE"],))
    db.commit()
    assert users_client.post("/users/login", json={"username": "employee", "password": "ValidPass123"}).status_code == 403


def test_list_users_permissions_and_safe_fields(users_client, auth_headers):
    for role in ("ADMIN", "AUDITOR"):
        r = users_client.get("/users", headers=auth_headers[role])
        assert r.status_code == 200
        assert len(r.get_json()["users"]) == 4
        assert all("password_hash" not in u for u in r.get_json()["users"])
    assert users_client.get("/users", headers=auth_headers["EMPLOYEE"]).status_code == 403
    assert users_client.get("/users").status_code == 401
    assert users_client.get("/users", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_get_user_self_admin_and_missing(users_client, auth_headers):
    own = users_client.get("/users/employee", headers=auth_headers["EMPLOYEE"])
    assert own.status_code == 200
    assert own.get_json()["user"]["username"] == "employee"
    assert users_client.get("/users/admin", headers=auth_headers["EMPLOYEE"]).status_code == 403
    assert users_client.get("/users/employee", headers=auth_headers["ADMIN"]).status_code == 200
    assert users_client.get("/users/doesnotexist", headers=auth_headers["ADMIN"]).status_code == 404


def test_update_self_permission_validation_and_persistence(users_client, db, accounts, auth_headers):
    uid = accounts["EMPLOYEE"]
    url = f"/users/{uid}"
    r = users_client.put(url, headers=auth_headers["EMPLOYEE"], json={"department": "Security"})
    assert r.status_code == 200
    assert db.execute("SELECT department FROM users WHERE id = ?", (uid,)).fetchone()[0] == "Security"
    assert users_client.put(url, headers=auth_headers["EMPLOYEE"], json={"role": "ADMIN"}).status_code == 400
    assert users_client.put(f"/users/{accounts['ADMIN']}", headers=auth_headers["EMPLOYEE"], json={"department": "X"}).status_code == 403
    assert users_client.put("/users/999999", headers=auth_headers["ADMIN"], json={"department": "X"}).status_code == 404
    assert users_client.put(url, headers=auth_headers["ADMIN"], json={"email": "admin@example.test"}).status_code == 409


def test_delete_admin_only_and_fk_protection(users_client, db, accounts, auth_headers):
    uid = accounts["EMPLOYEE"]
    assert users_client.delete(f"/users/{uid}", headers=auth_headers["EMPLOYEE"]).status_code == 403
    assert users_client.delete(f"/users/{accounts['ADMIN']}", headers=auth_headers["ADMIN"]).status_code == 403
    assert users_client.delete("/users/999999", headers=auth_headers["ADMIN"]).status_code == 404
    r = users_client.delete(f"/users/{uid}", headers=auth_headers["ADMIN"])
    assert r.status_code == 200
    assert db.execute("SELECT id FROM users WHERE id = ?", (uid,)).fetchone() is None
