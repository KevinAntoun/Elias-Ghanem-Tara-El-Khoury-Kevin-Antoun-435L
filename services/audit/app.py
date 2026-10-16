"""Start the audit Flask service: python -m services.audit.app"""

import os
from shared.app_factory import create_app
from shared.config import service_port
from .routes import bp

app = create_app("audit", [bp])

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=service_port("audit"), debug=False, use_reloader=False)
