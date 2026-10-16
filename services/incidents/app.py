"""Start the incidents Flask service: python -m services.incidents.app"""

import os
from shared.app_factory import create_app
from shared.config import service_port
from .routes import bp

app = create_app("incidents", [bp])

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=service_port("incidents"), debug=False, use_reloader=False)
