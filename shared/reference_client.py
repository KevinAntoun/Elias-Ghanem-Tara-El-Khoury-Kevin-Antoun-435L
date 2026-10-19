"""Purpose-scoped authenticated HTTP lookups for foreign service references.

Database foreign keys still enforce integrity, but business validation is
performed by the domain-owning Flask service, never by reading foreign tables.
"""

import os
import requests
from flask import current_app
from shared.config import service_url


class ReferenceUnavailable(Exception):
    """A required owning service could not validate a reference."""


def _get(owner, path):
    caller = current_app.name.removeprefix("services.")
    credential = os.getenv(f"REFERENCE_TOKEN_{owner.upper()}_{caller.upper()}")
    if not credential or len(credential) < 32:
        raise ReferenceUnavailable(f"Reference access to {owner} is not configured.")
    try:
        response = requests.get(
            f"{service_url(owner)}{path}",
            headers={"Authorization": f"Service {credential}", "X-Service-Name": caller},
            timeout=2,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Invalid response")
        return data
    except (requests.RequestException, ValueError) as exc:
        raise ReferenceUnavailable(f"Reference service {owner} is unavailable.") from exc


def lookup_user(user_id):
    response = _get("users", f"/internal/references/users/{user_id}")
    if response is None:
        return None
    value = response.get("user")
    if not isinstance(value, dict) or value.get("id") != user_id:
        raise ReferenceUnavailable("Users returned an invalid reference.")
    return value


def lookup_asset(asset_id):
    response = _get("assets", f"/internal/references/assets/{asset_id}")
    if response is None:
        return None
    value = response.get("asset")
    if not isinstance(value, dict) or value.get("id") != asset_id:
        raise ReferenceUnavailable("Assets returned an invalid reference.")
    return value


def analyst_asset_ids(analyst_id):
    response = _get("incidents", f"/internal/references/incidents/analyst/{analyst_id}/assets")
    if not isinstance(response, dict) or not isinstance(response.get("asset_ids"), list):
        raise ReferenceUnavailable("Incidents returned invalid assignments.")
    ids = response["asset_ids"]
    if any(type(value) is not int or value <= 0 for value in ids):
        raise ReferenceUnavailable("Incidents returned invalid assignment IDs.")
    return ids


def use_local_references():
    """Preserve isolated legacy unit tests; opt-in tests can exercise real HTTP."""
    return current_app.testing and not current_app.config.get("REFERENCE_HTTP_IN_TESTS", False)
