"""Tests for normalized event mapping and authenticated audit delivery."""
import requests
from shared.audit_events import audit_action, send_audit_event


def test_login_events():
    assert audit_action("users", "users.login_user", "POST", 200) == ("LOGIN_SUCCESS", "Information")
    assert audit_action("users", "users.login_user", "POST", 401) == ("LOGIN_FAILED", "Warning")


def test_mutation_and_denial_events():
    assert audit_action("threats", "threats.delete_threat", "DELETE", 200) == ("THREATS_DELETED", "Warning")
    assert audit_action("threats", "threats.get_threat", "GET", 403) == ("ACCESS_DENIED", "Warning")
    assert audit_action("threats", "threats.get_threat", "GET", 200) is None
    assert audit_action("threats", "threats.create_threat", "POST", 400) is None


def test_unconfigured_credential_does_not_make_http_call(monkeypatch):
    monkeypatch.delenv("AUDIT_TOKEN_THREATS", raising=False)
    def fail(*a, **kw):
        raise AssertionError("should not make request without credentials")
    monkeypatch.setattr("shared.audit_events.requests.post", fail)
    assert send_audit_event("threats", "THREATS_CREATED", "Created") is False


def test_authenticated_event(monkeypatch):
    monkeypatch.setenv("AUDIT_TOKEN_THREATS", "t" * 48)
    calls = []
    class Response:
        status_code = 201
        def raise_for_status(self):
            pass
    def fake_post(url, *, headers, json, timeout):
        calls.append((url, headers, json, timeout))
        return Response()
    monkeypatch.setattr("shared.audit_events.requests.post", fake_post)
    assert send_audit_event("threats", "THREAT_CREATED", "Created", user_id=7)
    assert calls[0][1]["X-Service-Name"] == "threats"
    assert calls[0][2]["user_id"] == 7
    assert calls[0][2]["related_service"] == "threats"


def test_failed_delivery_reported(monkeypatch):
    monkeypatch.setenv("AUDIT_TOKEN_THREATS", "t" * 48)
    def fake_post(*args, **kwargs):
        raise requests.ConnectionError("unavailable")
    monkeypatch.setattr("shared.audit_events.requests.post", fake_post)
    assert send_audit_event("threats", "THREAT_CREATED", "Created") is False
