"""Start the notifications Flask service: python -m services.notifications.app"""

import os
from shared.app_factory import create_app
from shared.config import service_port
from .routes import bp

app = create_app("notifications", [bp])

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=service_port("notifications"), debug=False, use_reloader=False)
