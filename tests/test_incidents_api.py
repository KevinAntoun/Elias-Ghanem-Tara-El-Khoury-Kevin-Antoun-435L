"""Incidents API: reporting, read scope, assignment, lifecycle and investigation notes."""


def incident_body(asset_id):
    return {
        "title": "Suspicious login", "description": "Repeated failed authentication attempts",
        "category": "Unauthorized Access", "severity": "High", "affected_asset_id": asset_id,
    }


def test_create_as_employee_and_db_record(incidents_client, db, accounts, asset_id, auth_headers):
    r = incidents_client.post("/incidents", headers=auth_headers["EMPLOYEE"], json=incident_body(asset_id))
    assert r.status_code == 201
    record = r.get_json()["incident"]
    assert record["reporter_id"] == accounts["EMPLOYEE"]
    assert record["status"] == "Open"
    assert db.execute("SELECT id FROM incidents WHERE id = ?", (record["id"],)).fetchone() is not None


def test_create_validations_and_permissions(incidents_client, accounts, asset_id, auth_headers):
    valid = incident_body(asset_id)
    assert incidents_client.post("/incidents", json=valid).status_code == 401
    assert incidents_client.post("/incidents", headers=auth_headers["ANALYST"], json=valid).status_code == 403
    assert incidents_client.post("/incidents", headers=auth_headers["EMPLOYEE"], json={**valid, "severity": "Extreme"}).status_code == 400
    assert incidents_client.post("/incidents", headers=auth_headers["EMPLOYEE"], json={**valid, "affected_asset_id": 999999}).status_code == 400
    assert incidents_client.post("/incidents", headers=auth_headers["EMPLOYEE"], json={**valid, "reporter_id": accounts["ADMIN"]}).status_code == 403


def test_list_detail_scope_and_missing(incidents_client, db, accounts, incident_id, auth_headers):
    assert incidents_client.get("/incidents", headers=auth_headers["ADMIN"]).status_code == 200
    assert incidents_client.get("/incidents", headers=auth_headers["AUDITOR"]).status_code == 200
    assert incidents_client.get("/incidents", headers=auth_headers["EMPLOYEE"]).status_code == 403
    for role in ("ADMIN", "AUDITOR", "ANALYST", "EMPLOYEE"):
        assert incidents_client.get(f"/incidents/{incident_id}", headers=auth_headers[role]).status_code == 200
    assert incidents_client.get("/incidents/999999", headers=auth_headers["ADMIN"]).status_code == 404
    db.execute("UPDATE incidents SET assigned_analyst_id = NULL WHERE id = ?", (incident_id,))
    db.commit()
    assert incidents_client.get(f"/incidents/{incident_id}", headers=auth_headers["ANALYST"]).status_code == 403


def test_assign_analyst_and_reject_other_roles(incidents_client, db, accounts, incident_id, auth_headers):
    url = f"/incidents/{incident_id}/assign"
    assert incidents_client.put(url, headers=auth_headers["EMPLOYEE"], json={"assigned_analyst_id": accounts["ANALYST"]}).status_code == 403
    assert incidents_client.put(url, headers=auth_headers["ADMIN"], json={"assigned_analyst_id": accounts["EMPLOYEE"]}).status_code == 400
    assert incidents_client.put("/incidents/999999/assign", headers=auth_headers["ADMIN"], json={"assigned_analyst_id": accounts["ANALYST"]}).status_code == 404
    assert incidents_client.put(url, headers=auth_headers["ADMIN"], json={"assigned_analyst_id": accounts["ANALYST"]}).status_code == 200
    assert db.execute("SELECT assigned_analyst_id FROM incidents WHERE id = ?", (incident_id,)).fetchone()[0] == accounts["ANALYST"]


def test_status_progression_and_skip_rejected(incidents_client, db, incident_id, auth_headers):
    url = f"/incidents/{incident_id}/status"
    assert incidents_client.put(url, headers=auth_headers["EMPLOYEE"], json={"status": "Under Investigation"}).status_code == 403
    assert incidents_client.put(url, headers=auth_headers["ADMIN"], json={"status": "Closed"}).status_code == 409
    for value in ("Under Investigation", "Mitigated", "Resolved", "Closed"):
        r = incidents_client.put(url, headers=auth_headers["ANALYST"], json={"status": value})
        assert r.status_code == 200, r.get_json()
    row = db.execute("SELECT status, resolution_date FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    assert row["status"] == "Closed"
    assert row["resolution_date"] is not None
    assert incidents_client.put(url, headers=auth_headers["ADMIN"], json={"status": "Closed"}).status_code == 409


def test_unassigned_analyst_cannot_change_status(incidents_client, db, incident_id, auth_headers):
    db.execute("UPDATE incidents SET assigned_analyst_id = NULL WHERE id = ?", (incident_id,))
    db.commit()
    assert incidents_client.put(f"/incidents/{incident_id}/status", headers=auth_headers["ANALYST"], json={"status": "Under Investigation"}).status_code == 403


def test_note_persistence_permission_and_closed_rejection(incidents_client, db, incident_id, auth_headers):
    url = f"/incidents/{incident_id}/notes"
    assert incidents_client.post(url, headers=auth_headers["EMPLOYEE"], json={"content": "test"}).status_code == 403
    assert incidents_client.post(url, headers=auth_headers["ADMIN"], json={"content": "  "}).status_code == 400
    r = incidents_client.post(url, headers=auth_headers["ANALYST"], json={"content": "Checked logs"})
    assert r.status_code == 201
    assert db.execute("SELECT content FROM investigation_notes WHERE id = ?", (r.get_json()["note"]["id"],)).fetchone()[0] == "Checked logs"
    detail = incidents_client.get(f"/incidents/{incident_id}", headers=auth_headers["ADMIN"])
    assert len(detail.get_json()["incident"]["investigation_notes"]) == 1
    db.execute("UPDATE incidents SET status = 'Closed' WHERE id = ?", (incident_id,))
    db.commit()
    assert incidents_client.post(url, headers=auth_headers["ADMIN"], json={"content": "late"}).status_code == 409
