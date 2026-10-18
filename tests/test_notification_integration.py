"""Regression checks for internal notifications and automatic alert producers."""

import sqlite3

import pytest
import requests

from shared.app_factory import create_app
from shared import notification_events
from services.notifications.routes import bp as notifications_bp
import services.incidents.routes as incident_routes
import services.threats.routes as threat_routes
import services.vulnerabilities.routes as vulnerability_routes


SECRET = "notification-integration-test-key-" + "N" * 45


def _notice(user_id):
    return {
        "user_id": user_id,
        "title": "Assigned incident #1",
        "message": "Please investigate incident #1.",
        "notification_type": "Incident Assignment",
        "severity": "High",
    }


def _internal_headers(producer="incidents", credential=SECRET):
    return {
        "Authorization": f"Service {credential}",
        "X-Service-Name": producer,
    }


def test_internal_service_creates_notification(db_path, accounts, monkeypatch):
    monkeypatch.setenv("NOTIFICATION_TOKEN_INCIDENTS", SECRET)
    app = create_app("notifications", [notifications_bp])
    app.config.update(TESTING=True)
    response = app.test_client().post(
        "/notifications", json=_notice(accounts["ANALYST"]),
        headers=_internal_headers(),
    )
    assert response.status_code == 201, response.get_json()
    assert response.json["notification"]["status"] == "Unread"
    with sqlite3.connect(db_path) as db:
        row = db.execute("SELECT user_id, notification_type FROM notifications").fetchone()
    assert row == (accounts["ANALYST"], "Incident Assignment")


@pytest.mark.parametrize("headers", [
    {},
    {"X-Service-Name": "incidents"},
    _internal_headers(credential="wrong"),
    _internal_headers(producer="assets"),
])
def test_internal_notification_auth_fails_closed(db_path, accounts, monkeypatch, headers):
    monkeypatch.setenv("NOTIFICATION_TOKEN_INCIDENTS", SECRET)
    monkeypatch.setenv("NOTIFICATION_TOKEN_ASSETS", SECRET)
    app = create_app("notifications", [notifications_bp])
    app.config.update(TESTING=True)
    response = app.test_client().post(
        "/notifications", json=_notice(accounts["ANALYST"]), headers=headers
    )
    assert response.status_code == 401
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM notifications").fetchone()[0] == 0


def test_audit_token_does_not_grant_notification_access(db_path, accounts, monkeypatch):
    monkeypatch.setenv("AUDIT_TOKEN_INCIDENTS", SECRET)
    monkeypatch.delenv("NOTIFICATION_TOKEN_INCIDENTS", raising=False)
    app = create_app("notifications", [notifications_bp])
    app.config.update(TESTING=True)
    response = app.test_client().post(
        "/notifications", json=_notice(accounts["ANALYST"]),
        headers=_internal_headers(),
    )
    assert response.status_code == 401


def test_admin_can_still_create_notification(db_path, accounts, auth_headers):
    app = create_app("notifications", [notifications_bp])
    app.config.update(TESTING=True)
    response = app.test_client().post(
        "/notifications", json=_notice(accounts["ANALYST"]),
        headers=auth_headers["ADMIN"],
    )
    assert response.status_code == 201, response.get_json()


def test_incident_reassignment_notifies_only_on_change(
    incidents_client, incident_id, accounts, auth_headers, db, monkeypatch
):
    calls = []
    monkeypatch.setattr(incident_routes, "send_notification_event", lambda *a: calls.append(a) or True)
    # The seeded incident already belongs to this analyst: do not notify again.
    url = f"/incidents/{incident_id}/assign"
    same = incidents_client.put(
        url, json={"assigned_analyst_id": accounts["ANALYST"]},
        headers=auth_headers["ADMIN"],
    )
    assert same.status_code == 200
    assert calls == []

    cursor = db.execute(
        """INSERT INTO users (full_name, username, email, password_hash, role, account_status)
           VALUES (?, ?, ?, ?, 'ANALYST', 'Active')""",
        ("Second Analyst", "analyst2", "analyst2@example.test", "hash"),
    )
    db.commit()
    new_analyst = cursor.lastrowid
    response = incidents_client.put(
        url, json={"assigned_analyst_id": new_analyst}, headers=auth_headers["ADMIN"]
    )
    assert response.status_code == 200, response.get_json()
    assert len(calls) == 1
    assert calls[0][0:2] == ("incidents", new_analyst)
    assert calls[0][4] == "Incident Assignment"
    assert db.execute(
        "SELECT assigned_analyst_id FROM incidents WHERE id=?", (incident_id,)
    ).fetchone()[0] == new_analyst


def test_critical_threat_create_emits_configured_alert(
    db_path, auth_headers, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        threat_routes, "send_critical_security_alert", lambda *a: calls.append(a)
    )
    app = create_app("threats", [threat_routes.bp])
    app.config.update(TESTING=True)
    response = app.test_client().post(
        "/threats", json={
            "threat_type": "IP Address", "threat_value": "192.0.2.71",
            "severity": "Critical",
        }, headers=auth_headers["ADMIN"],
    )
    assert response.status_code == 201, response.get_json()
    assert calls == [("threats", response.json["threat"]["id"], "Critical")]


def test_noncritical_threat_does_not_send_alert(db_path, auth_headers, monkeypatch):
    recipients = []
    monkeypatch.setenv("SECURITY_ALERT_RECIPIENT_IDS", "1")
    monkeypatch.setattr(notification_events, "send_notification_event", lambda *args: recipients.append(args))
    app = create_app("threats", [threat_routes.bp])
    app.config.update(TESTING=True)
    response = app.test_client().post(
        "/threats", json={
            "threat_type": "Domain", "threat_value": "example.com", "severity": "High",
        }, headers=auth_headers["ADMIN"],
    )
    assert response.status_code == 201
    assert recipients == []


def test_critical_vulnerability_create_emits_alert(db_path, asset_id, auth_headers, monkeypatch):
    calls = []
    monkeypatch.setattr(
        vulnerability_routes, "send_critical_security_alert", lambda *a: calls.append(a)
    )
    app = create_app("vulnerabilities", [vulnerability_routes.bp])
    app.config.update(TESTING=True)
    response = app.test_client().post(
        "/vulnerabilities", json={
            "title": "Critical vulnerability", "description": "Critical test case",
            "cve_identifier": "CVE-2024-3094", "cvss_score": 10.0,
            "severity": "Critical", "affected_asset_id": asset_id,
            "discovery_source": "Scanner",
        }, headers=auth_headers["ADMIN"],
    )
    assert response.status_code == 201, response.get_json()
    assert calls == [("vulnerabilities", response.json["vulnerability"]["id"], "Critical")]


def test_critical_threat_update_only_alerts_on_escalation(db_path, auth_headers, monkeypatch):
    calls = []
    monkeypatch.setattr(threat_routes, "send_critical_security_alert", lambda *a: calls.append(a))
    app = create_app("threats", [threat_routes.bp])
    app.config.update(TESTING=True)
    client = app.test_client()
    created = client.post("/threats", json={
        "threat_type": "IP Address", "threat_value": "192.0.2.75", "severity": "High"
    }, headers=auth_headers["ADMIN"])
    assert created.status_code == 201
    threat_id = created.json["threat"]["id"]
    response = client.put(f"/threats/{threat_id}", json={"severity": "Critical"},
                          headers=auth_headers["ADMIN"])
    assert response.status_code == 200
    assert calls == [("threats", threat_id, "High"), ("threats", threat_id, "Critical")]
    # High-level route calls the helper for creation, but the helper itself
    # only sends when severity is Critical. A description edit must not
    # re-notify for a previously critical record.
    changed = client.put(f"/threats/{threat_id}", json={"description": "Updated"},
                         headers=auth_headers["ADMIN"])
    assert changed.status_code == 200
    assert len(calls) == 2


def test_critical_vulnerability_update_only_on_escalation(
    db_path, asset_id, auth_headers, monkeypatch
):
    calls = []
    monkeypatch.setattr(vulnerability_routes, "send_critical_security_alert", lambda *a: calls.append(a))
    app = create_app("vulnerabilities", [vulnerability_routes.bp])
    app.config.update(TESTING=True)
    client = app.test_client()
    created = client.post("/vulnerabilities", json={
        "title": "Serious flaw", "description": "Test case",
        "cve_identifier": "CVE-2024-3094", "cvss_score": 8.0,
        "severity": "High", "affected_asset_id": asset_id,
        "discovery_source": "Scanner",
    }, headers=auth_headers["ADMIN"])
    assert created.status_code == 201, created.get_json()
    vuln_id = created.json["vulnerability"]["id"]
    updated = client.put(f"/vulnerabilities/{vuln_id}", json={
        "severity": "Critical", "cvss_score": 10.0,
    }, headers=auth_headers["ADMIN"])
    assert updated.status_code == 200, updated.get_json()
    assert calls == [("vulnerabilities", vuln_id, "High"),
                     ("vulnerabilities", vuln_id, "Critical")]


def test_notification_client_posts_authenticated(monkeypatch):
    monkeypatch.setenv("NOTIFICATION_TOKEN_INCIDENTS", SECRET)
    sent = []

    class Response:
        status_code = 201
        def raise_for_status(self):
            return None

    def fake_post(url, **kwargs):
        sent.append((url, kwargs))
        return Response()

    monkeypatch.setattr(notification_events.requests, "post", fake_post)
    assert notification_events.send_notification_event(
        "incidents", 7, "Incident #5", "Assigned to you", "Incident Assignment", "High"
    )
    assert sent[0][0].endswith("/notifications")
    assert sent[0][1]["headers"] == _internal_headers()
    assert sent[0][1]["json"]["user_id"] == 7
    assert sent[0][1]["timeout"] > 0


def test_notification_client_fails_safely_on_unavailable_service(monkeypatch):
    monkeypatch.setenv("NOTIFICATION_TOKEN_INCIDENTS", SECRET)

    def offline(*args, **kwargs):
        raise requests.ConnectionError("test outage")

    monkeypatch.setattr(notification_events.requests, "post", offline)
    assert notification_events.send_notification_event(
        "incidents", 7, "Incident #5", "Assigned to you", "Incident Assignment", "High"
    ) is False


def test_configured_recipient_filter_and_deduplication(monkeypatch):
    monkeypatch.setenv("SECURITY_ALERT_RECIPIENT_IDS", "5, 3, 5, invalid, -2, 0")
    assert notification_events.security_alert_recipients() == [3, 5]
    observed = []
    monkeypatch.setattr(
        notification_events, "send_notification_event",
        lambda *args: observed.append(args) or True,
    )
    delivered = notification_events.send_critical_security_alert("threats", 42, "Critical")
    assert delivered == 2
    assert [entry[1] for entry in observed] == [3, 5]
    assert all(entry[4] == "Threat Alert" for entry in observed)


def test_audit_http_hook_skips_network_by_default(db_path, auth_headers, monkeypatch):
    import shared.app_factory as factory

    def forbidden(*args, **kwargs):
        raise AssertionError("Test client unexpectedly attempted an audit delivery")

    monkeypatch.setattr(factory, "send_audit_event", forbidden)
    app = create_app("threats", [threat_routes.bp])
    app.config.update(TESTING=True)
    response = app.test_client().post(
        "/threats", json={
            "threat_type": "Domain", "threat_value": "safe.example", "severity": "Low"
        }, headers=auth_headers["ADMIN"],
    )
    assert response.status_code == 201


def test_audit_http_hook_delivers_only_when_enabled(db_path, auth_headers, monkeypatch):
    import shared.app_factory as factory

    events = []
    monkeypatch.setattr(factory, "send_audit_event", lambda *args, **kwargs: events.append((args, kwargs)))
    app = create_app("threats", [threat_routes.bp])
    app.config.update(TESTING=True, AUDIT_DELIVERY_IN_TESTS=True)
    response = app.test_client().post(
        "/threats", json={
            "threat_type": "Domain", "threat_value": "audit.example", "severity": "Low"
        }, headers=auth_headers["ADMIN"],
    )
    assert response.status_code == 201
    assert len(events) == 1
    assert events[0][0][0:2] == ("threats", "THREATS_CREATED")
    assert events[0][1]["user_id"] is not None
