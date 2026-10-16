"""System security statistics API routes.

Responsible student: Student B (replace with full name).
TODO: implement and document these required endpoints:
    - GET /reports/summary
    - GET /reports/incidents
    - GET /reports/assets
    - GET /reports/threats
    - GET /reports/vulnerabilities
    - GET /reports/activity
"""

from flask import Blueprint

bp = Blueprint("reports", __name__, url_prefix="/reports")

# Add graded API routes here. Do not mark them complete until implemented,
# protected, tested in Postman, and documented.


@bp.get("/dependencies")
def check_dependencies():
    """Demonstration only: check two other services using HTTP requests.

    This is NOT a graded security-report endpoint. It proves that the
    services can communicate while running in separate Flask processes.
    """
    import requests
    from flask import jsonify
    from shared.service_client import request_json

    details = {}
    all_ok = True
    for dependency in ("users", "assets"):
        try:
            details[dependency] = request_json(dependency, "/health")
        except (requests.exceptions.RequestException, ValueError) as error:
            details[dependency] = {"status": "unavailable", "error_type": type(error).__name__}
            all_ok = False
    return jsonify({"status": "ok" if all_ok else "error", "dependencies": details}), (200 if all_ok else 503)
