"""Consistent Flask setup for separately runnable services."""

from flask import Blueprint, Flask, jsonify
from werkzeug.exceptions import HTTPException

from shared.database import close_db


def create_app(name: str, blueprints: list[Blueprint]) -> Flask:
    """Create a service app and register its endpoint Blueprints."""
    app = Flask(f"services.{name}")
    app.teardown_appcontext(close_db)

    for blueprint in blueprints:
        app.register_blueprint(blueprint)

    @app.get("/health")
    def health():
        """Basic health endpoint; does not verify dependencies or database."""
        return jsonify({"status": "ok", "service": name}), 200

    @app.errorhandler(HTTPException)
    def http_error(error: HTTPException):
        """Convert Flask-generated HTTP errors into a consistent JSON shape."""
        return jsonify({"status": "error", "message": error.description}), error.code

    return app
