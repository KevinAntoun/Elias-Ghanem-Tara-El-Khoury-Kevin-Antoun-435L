"""Authentication for trusted service-to-service Audit requests.

Keeps machine credentials separate from user JWTs. An internal service sends
Authorization: Service <secret> and X-Service-Name: <name>. The header naming
the service is never trusted without a matching configured secret.

Configure a different high-entropy AUDIT_TOKEN_<SERVICE> secret for each
trusted producer on the Audit service. Do not expose these tokens to clients.
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


def current_internal_service():
    """Name of the authenticated producer, or None for a user request."""
    return getattr(g, "audit_internal_service", None)


def require_admin_or_service(view_function):
    """Authorize an ADMIN JWT or a configured internal service credential.

    ADMIN identities are checked using the existing shared JWT decorator.
    Internal callers must provide a separately provisioned 32+-character
    secret for a permitted service; absent/misconfigured secrets fail closed.
    """
    admin_view = require_roles("ADMIN")(view_function)

    @wraps(view_function)
    def wrapper(*args, **kwargs):
        authorization = request.headers.get("Authorization", "")
        parts = authorization.split()

        if parts and parts[0].lower() == "service":
            if len(parts) != 2:
                return jsonify({
                    "status": "error", "message": "Invalid service credentials."
                }), 401

            service = request.headers.get("X-Service-Name", "").strip().lower()
            if service not in PRODUCER_SERVICES:
                return jsonify({
                    "status": "error", "message": "Invalid service credentials."
                }), 401

            expected = os.getenv(f"AUDIT_TOKEN_{service.upper()}")
            provided = parts[1]
            if (
                not expected
                or len(expected) < 32
                or not secrets.compare_digest(provided, expected)
            ):
                return jsonify({
                    "status": "error", "message": "Invalid service credentials."
                }), 401

            g.audit_internal_service = service
            return view_function(*args, **kwargs)

        return admin_view(*args, **kwargs)

    return wrapper
