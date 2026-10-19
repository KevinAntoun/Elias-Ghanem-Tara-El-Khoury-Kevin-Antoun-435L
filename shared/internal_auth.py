"""Authenticate trusted machine callers separately from human JWT users.

Each destination service uses its own per-producer credentials:
- AUDIT_TOKEN_<SERVICE> protects POST /logs
- NOTIFICATION_TOKEN_<SERVICE> protects POST /notifications

Clients must present ``Authorization: Service <secret>`` and the verified
``X-Service-Name``. Mere possession of a service-name header proves nothing.
Secrets must be high-entropy, at least 32 characters, and configured on both
sides. Keep them out of version control. Use TLS outside localhost.
"""

import os
import secrets
from functools import wraps

from flask import g, jsonify, request

from shared.auth import require_roles


PRODUCER_SERVICES = frozenset({
    "users", "assets", "incidents", "threats", "vulnerabilities",
    "notifications", "playbooks", "reports",
})
NOTIFICATION_PRODUCERS = frozenset({"incidents", "threats", "vulnerabilities"})


def current_internal_service():
    """Verified producer name for the Audit service, if any."""
    return getattr(g, "audit_internal_service", None)


def current_notification_service():
    """Verified producer name for the Notification service, if any."""
    return getattr(g, "notification_internal_service", None)


def _admin_or_service(view_function, *, producers, secret_prefix, context_key):
    """Enforce ADMIN JWT or a purpose-scoped and authenticated machine token."""
    admin_view = require_roles("ADMIN")(view_function)

    @wraps(view_function)
    def wrapper(*args, **kwargs):
        authorization = request.headers.get("Authorization", "")
        parts = authorization.split()
        if parts and parts[0].lower() == "service":
            service = request.headers.get("X-Service-Name", "").strip().lower()
            if len(parts) != 2 or service not in producers:
                return jsonify({
                    "status": "error", "message": "Invalid service credentials."
                }), 401
            expected = os.getenv(f"{secret_prefix}_{service.upper()}")
            if (
                not expected
                or len(expected) < 32
                or not secrets.compare_digest(parts[1], expected)
            ):
                return jsonify({
                    "status": "error", "message": "Invalid service credentials."
                }), 401
            setattr(g, context_key, service)
            return view_function(*args, **kwargs)
        return admin_view(*args, **kwargs)

    return wrapper


def require_admin_or_service(view_function):
    """Audit writes: ADMIN or an authenticated Audit event producer."""
    return _admin_or_service(
        view_function,
        producers=PRODUCER_SERVICES,
        secret_prefix="AUDIT_TOKEN",
        context_key="audit_internal_service",
    )


def require_admin_or_notification_service(view_function):
    """Notification writes: ADMIN or an approved notification producer."""
    return _admin_or_service(
        view_function,
        producers=NOTIFICATION_PRODUCERS,
        secret_prefix="NOTIFICATION_TOKEN",
        context_key="notification_internal_service",
    )
