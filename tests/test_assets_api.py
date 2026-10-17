"""Assets API: CRUD, scoped search, owner checks, and relationship constraints."""


def body(owner):
    return {
        "name": "New Router", "asset_type": "Network Equipment",
        "ip_address": "10.2.3.4", "operating_system": "NetworkOS",
        "department": "IT", "owner_id": owner,
        "location": "Office", "criticality": "High", "status": "Active",
    }


def test_create_and_database_persistence(assets_client, db, accounts, auth_headers):
    r = assets_client.post("/assets", headers=auth_headers["ADMIN"], json=body(accounts["EMPLOYEE"]))
    assert r.status_code == 201
    asset = r.get_json()["asset"]
    assert asset["name"] == "New Router"
    assert db.execute("SELECT owner_id FROM assets WHERE id = ?", (asset["id"],)).fetchone()[0] == accounts["EMPLOYEE"]


def test_create_validation_and_permissions(assets_client, accounts, auth_headers):
    valid = body(accounts["EMPLOYEE"])
    assert assets_client.post("/assets", json=valid).status_code == 401
    assert assets_client.post("/assets", headers=auth_headers["EMPLOYEE"], json=valid).status_code == 403
    assert assets_client.post("/assets", headers=auth_headers["ADMIN"], json={**valid, "ip_address": "999.2.3.4"}).status_code == 400
    assert assets_client.post("/assets", headers=auth_headers["ADMIN"], json={**valid, "owner_id": 999999}).status_code == 400
    assert assets_client.post("/assets", headers=auth_headers["ADMIN"], json={**valid, "criticality": "Extreme"}).status_code == 400
    assert assets_client.post("/assets", headers=auth_headers["ADMIN"], json={"name": "Incomplete"}).status_code == 400


def test_list_and_detail(assets_client, asset_id, auth_headers):
    assert assets_client.get("/assets", headers=auth_headers["ADMIN"]).status_code == 200
    assert assets_client.get("/assets", headers=auth_headers["AUDITOR"]).status_code == 200
    assert assets_client.get("/assets", headers=auth_headers["EMPLOYEE"]).status_code == 403
    r = assets_client.get(f"/assets/{asset_id}", headers=auth_headers["ADMIN"])
    assert r.status_code == 200
    assert r.get_json()["asset"]["id"] == asset_id
    assert assets_client.get("/assets/999999", headers=auth_headers["ADMIN"]).status_code == 404


def test_search_and_invalid_search(assets_client, asset_id, auth_headers):
    r = assets_client.get("/assets/search?name=Fixture", headers=auth_headers["ADMIN"])
    assert r.status_code == 200
    assert any(a["id"] == asset_id for a in r.get_json()["assets"])
    assert assets_client.get("/assets/search?criticality=High", headers=auth_headers["AUDITOR"]).status_code == 200
    assert assets_client.get("/assets/search?unknown=x", headers=auth_headers["ADMIN"]).status_code == 400
    assert assets_client.get("/assets/search", headers=auth_headers["ADMIN"]).status_code == 400
    assert assets_client.get("/assets/search?name=Fixture", headers=auth_headers["EMPLOYEE"]).status_code == 403


def test_analyst_sees_only_assigned_incident_assets(assets_client, db, accounts, asset_id, incident_id, auth_headers):
    assert assets_client.get(f"/assets/{asset_id}", headers=auth_headers["ANALYST"]).status_code == 200
    r = assets_client.get("/assets/search?name=Fixture", headers=auth_headers["ANALYST"])
    assert [a["id"] for a in r.get_json()["assets"]] == [asset_id]
    cur = db.execute("INSERT INTO assets (name, asset_type, owner_id, criticality) VALUES (?, ?, ?, ?)",
                     ("Unrelated asset", "Server", accounts["EMPLOYEE"], "Low"))
    db.commit()
    assert assets_client.get(f"/assets/{cur.lastrowid}", headers=auth_headers["ANALYST"]).status_code == 403


def test_update_valid_invalid_and_permissions(assets_client, db, asset_id, auth_headers):
    url = f"/assets/{asset_id}"
    assert assets_client.put(url, headers=auth_headers["EMPLOYEE"], json={"status": "Inactive"}).status_code == 403
    assert assets_client.put(url, headers=auth_headers["ADMIN"], json={"criticality": "Impossible"}).status_code == 400
    assert assets_client.put("/assets/999999", headers=auth_headers["ADMIN"], json={"status": "Inactive"}).status_code == 404
    r = assets_client.put(url, headers=auth_headers["ADMIN"], json={"status": "Under Maintenance"})
    assert r.status_code == 200
    assert db.execute("SELECT status FROM assets WHERE id = ?", (asset_id,)).fetchone()[0] == "Under Maintenance"


def test_delete_and_fk_constraint(assets_client, db, accounts, asset_id, incident_id, auth_headers):
    assert assets_client.delete(f"/assets/{asset_id}", headers=auth_headers["EMPLOYEE"]).status_code == 403
    assert assets_client.delete(f"/assets/{asset_id}", headers=auth_headers["ADMIN"]).status_code == 409
    cur = db.execute("INSERT INTO assets (name, asset_type, owner_id, criticality) VALUES (?, ?, ?, ?)",
                     ("Disposable", "Laptop", accounts["EMPLOYEE"], "Low"))
    db.commit()
    uid = cur.lastrowid
    assert assets_client.delete(f"/assets/{uid}", headers=auth_headers["ADMIN"]).status_code == 200
    assert db.execute("SELECT id FROM assets WHERE id = ?", (uid,)).fetchone() is None
    assert assets_client.delete("/assets/999999", headers=auth_headers["ADMIN"]).status_code == 404
