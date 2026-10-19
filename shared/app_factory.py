"""Consistent Flask setup for separately runnable services."""

from flask import Blueprint, Flask, jsonify, g, request
from werkzeug.exceptions import HTTPException

from shared.database import close_db
from shared.audit_events import audit_action, send_audit_event
from shared.reference_api import register_reference_routes
from shared.reference_client import ReferenceUnavailable


def create_app(name: str, blueprints: list[Blueprint]) -> Flask:
    """Create a service app and register its endpoint Blueprints."""
    app = Flask(f"services.{name}")
    app.teardown_appcontext(close_db)

    for blueprint in blueprints:
        app.register_blueprint(blueprint)
    register_reference_routes(app, name)

    @app.after_request
    def record_security_event(response):
        """Record security-relevant results without exposing request contents.

        Never send Audit its own events, avoiding recursion. Requests to /health
        and starter dependency checks are not audit events. Delivery errors are
        logged by the helper and do not mask the original API response.
        """
        if name == "audit" or request.path == "/health" or request.path.startswith("/internal/"):
            return response
        # Running pytest against a configured .env must not deliver real events.
        # Targeted integration tests can explicitly opt into network delivery.
        if app.testing and not app.config.get("AUDIT_DELIVERY_IN_TESTS", False):
            return response
        event = getattr(g, "audit_action_override", None) if 200 <= response.status_code < 300 else None
        if event is None:
            event = audit_action(name, request.endpoint, request.method, response.status_code)
        if event is not None:
            action, severity = event
            actor = getattr(g, "current_user", None)
            user_id = actor["id"] if actor else None
            # Login success is public and does not set g.current_user. Obtain
            # its actor safely from the just-produced response (never JWT).
            if action == "LOGIN_SUCCESS":
                payload = response.get_json(silent=True)
                if isinstance(payload, dict) and isinstance(payload.get("user"), dict):
                    user_id = payload["user"].get("id")
            elif action == "USER_CREATED":
                payload = response.get_json(silent=True)
                if isinstance(payload, dict) and isinstance(payload.get("user"), dict):
                    user_id = payload["user"].get("id")
            send_audit_event(
                name, action,
                getattr(g, "audit_description_override", None) or f"{request.method} {request.endpoint or chr(45)} returned HTTP {response.status_code}",
                severity=severity, user_id=user_id,
            )
        return response

    @app.errorhandler(ReferenceUnavailable)
    def reference_unavailable(_error):
        return jsonify({"status": "error", "message": "A required service is unavailable."}), 503

    @app.get("/health")
    def health():
        """Basic health endpoint; does not verify dependencies or database."""
        return jsonify({"status": "ok", "service": name}), 200

    @app.errorhandler(HTTPException)
    def http_error(error: HTTPException):
        """Convert Flask-generated HTTP errors into a consistent JSON shape."""
        return jsonify({"status": "error", "message": error.description}), error.code

    return app
