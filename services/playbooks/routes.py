"""Response playbooks and actions API routes.

Responsible student: Student C (replace with full name).
TODO: implement and document these required endpoints:
    - POST /playbooks
    - GET /playbooks
    - GET /playbooks/<id>
    - POST /playbooks/<id>/actions
    - PUT /actions/<id>/status
    - DELETE /playbooks/<id>
"""

from flask import Blueprint

bp = Blueprint("playbooks", __name__, url_prefix="/playbooks")

# Add graded API routes here. Do not mark them complete until implemented,
# protected, tested in Postman, and documented.

# The required PUT /actions/<id>/status is outside /playbooks.
actions_bp = Blueprint("actions", __name__, url_prefix="/actions")
