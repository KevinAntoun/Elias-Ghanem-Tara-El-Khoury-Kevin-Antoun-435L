"""Minimal service-to-service HTTP helper.

This does not implement authentication: add verified service credentials or
forwarded user credentials in a deliberate, secure way for protected routes.
"""

import requests
from shared.config import service_url


def request_json(service: str, path: str, *, token: str | None = None,
                 method: str = "GET", json_body: dict | None = None) -> dict:
    """Call another service via HTTP and decode its JSON response.

    Raises ``requests.exceptions.RequestException`` for connectivity or
    non-2xx HTTP status; the caller decides how to handle such failures.
    """
    if not path.startswith("/"):
        raise ValueError("HTTP path must start with '/'")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    response = requests.request(
        method=method.upper(),
        url=f"{service_url(service)}{path}",
        json=json_body,
        headers=headers,
        timeout=3,
    )
    response.raise_for_status()
    return response.json()
