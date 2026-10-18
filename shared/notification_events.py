"""Best-effort authenticated delivery of notifications over HTTP.

Failing delivery does not undo a successful business write. Failures are
logged, not counted as successes; reliable delivery requires a durable outbox
or a retry policy in a subsequent integration step.

Incident Assignment: the assigned active analyst receives an alert.
Threat/Vulnerability Alert: only newly Critical records, to explicit recipients
listed in SECURITY_ALERT_RECIPIENT_IDS. No implicit access to another service's
user table or unsolicited broadcast is performed.
"""

import logging
import os

import requests
from flask import current_app, has_app_context

from shared.config import service_url
from shared.internal_auth import NOTIFICATION_PRODUCERS

LOG = logging.getLogger(__name__)


def send_notification_event(service, user_id, title, message, notification_type, severity):
    """Attempt one protected POST /notifications; return True only on HTTP 201."""
    if service not in NOTIFICATION_PRODUCERS:
        raise ValueError("Unknown notification producer")
    # Prevent an existing .env from causing real outbound calls during pytest.
    if (has_app_context() and current_app.testing
            and not current_app.config.get("NOTIFICATION_DELIVERY_IN_TESTS", False)):
        return False
    credential = os.getenv(f"NOTIFICATION_TOKEN_{service.upper()}")
    if not credential or len(credential) < 32:
        LOG.warning("Notification not delivered: %s credentials are not configured", service)
        return False
    if type(user_id) is not int or user_id <= 0:
        raise ValueError("Notification recipient must be a positive user ID")

    payload = {
        "user_id": user_id,
        "title": title,
        "message": message,
        "notification_type": notification_type,
        "severity": severity,
    }
    try:
        response = requests.post(
            f"{service_url('notifications')}/notifications",
            json=payload,
            headers={
                "Authorization": f"Service {credential}",
                "X-Service-Name": service,
            },
            timeout=2,
        )
        response.raise_for_status()
        if response.status_code != 201:
            LOG.warning("Unexpected notification response from %s: %s", service, response.status_code)
            return False
        return True
    except requests.RequestException as exc:
        LOG.warning("Notification delivery failed for %s: %s", service, exc)
        return False


def security_alert_recipients():
    """Read explicitly provisioned recipients; invalid items are ignored safely."""
    recipients = set()
    for part in os.getenv("SECURITY_ALERT_RECIPIENT_IDS", "").split(","):
        value = part.strip()
        if not value:
            continue
        if not value.isdecimal() or int(value) <= 0:
            LOG.warning("Ignoring invalid SECURITY_ALERT_RECIPIENT_IDS entry")
            continue
        recipients.add(int(value))
    return sorted(recipients)


def send_critical_security_alert(service, record_id, severity):
    """Send a new critical threat/vulnerability alert to configured user IDs."""
    types = {"threats": "Threat Alert", "vulnerabilities": "Vulnerability Alert"}
    if service not in types:
        raise ValueError("Unknown security alert type")
    if severity != "Critical":
        return 0
    label = "threat" if service == "threats" else "vulnerability"
    delivered = 0
    for recipient_id in security_alert_recipients():
        delivered += bool(send_notification_event(
            service,
            recipient_id,
            f"Critical {label} #{record_id}",
            f"A critical {label} record (ID {record_id}) needs security review.",
            types[service],
            severity,
        ))
    return delivered
