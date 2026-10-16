"""Start the playbooks Flask service: python -m services.playbooks.app"""

import os
from shared.app_factory import create_app
from shared.config import service_port
from .routes import bp, actions_bp

app = create_app("playbooks", [bp, actions_bp])

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=service_port("playbooks"), debug=False, use_reloader=False)
