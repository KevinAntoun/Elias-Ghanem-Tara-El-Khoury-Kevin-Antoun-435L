"""Start the threats Flask service: python -m services.threats.app"""

import os
from shared.app_factory import create_app
from shared.config import service_port
from .routes import bp

app = create_app("threats", [bp])

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=service_port("threats"), debug=False, use_reloader=False)
