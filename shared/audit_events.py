"""Best-effort authenticated HTTP delivery of audit events.

Delivery is attempted only when AUDIT_TOKEN_<SERVICE> is configured. Failed
requests are reported to application logs and do not pretend to be durable.
Production deployments should add a durable outbox/retry policy.
"""

import logging
import os
import requests
from shared.config import service_url

LOG = logging.getLogger(__name__)


def send_audit_event(service, action, description, severity="Information", user_id=None):
    """Send a non-sensitive audit event; return whether it was acknowledged.

    Never include passwords, tokens, request bodies or other secrets in description.
    ``user_id`` can be None for anonymous authentication failures.
    """
    if not isinstance(service, str) or not service.isidentifier():
        raise ValueError("Invalid producer service name")
    credential = os.getenv(f"AUDIT_TOKEN_{service.upper()}")
    if not credential or len(credential) < 32:
        LOG.warning("Audit event not delivered: credential for %s is unconfigured", service)
        return False
    payload = {
        "user_id": user_id,
        "action": action,
        "description": description,
        "severity": severity,
        "related_service": service,
    }
    try:
        response = requests.post(
            f"{service_url('audit')}/logs",
            headers={"Authorization": f"Service {credential}", "X-Service-Name": service},
            json=payload,
            timeout=1.5,
        )
        response.raise_for_status()
        return response.status_code == 201
    except (requests.RequestException, ValueError) as exc:
        LOG.warning("Audit event delivery failed for %s (%s): %s", service, action, exc)
        return False


def audit_action(service, endpoint, method, status):
    """Return canonical event action and severity for a finished request."""
    if service == "users" and endpoint == "users.login_user":
        if status == 200:
            return "LOGIN_SUCCESS", "Information"
        if status in (401, 403):
            return "LOGIN_FAILED", "Warning"
    if service == "users" and endpoint == "users.register_user" and status == 201:
        return "USER_CREATED", "Information"
    if status in (401, 403):
        return "ACCESS_DENIED", "Warning"
    if 200 <= status < 300 and method in ("POST", "PUT", "PATCH", "DELETE"):
        if service == "users" and method == "DELETE":
            return "USER_DELETED", "Warning"
        verb = {"POST": "CREATED", "PUT": "UPDATED", "PATCH": "UPDATED", "DELETE": "DELETED"}[method]
        return f"{service.upper()}_{verb}", "Warning" if method == "DELETE" else "Information"
    return None
