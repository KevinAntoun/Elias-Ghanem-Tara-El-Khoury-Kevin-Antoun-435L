"""Read-only smoke test against all nine running HTTP services.

1. Start the services with ``python -m scripts.run_all``.
2. Provision initial admin with ``python -m scripts.bootstrap_admin`` (once).
3. Run ``python -m scripts.integration_smoke`` in another terminal.

This script does not create/delete business records or print JWTs/passwords.
"""

import getpass
import sys

import requests
from shared.config import SERVICE_PORTS, service_url


READ_PATHS = {
    "users": ("/users",),
    "assets": ("/assets",),
    "incidents": ("/incidents",),
    "threats": ("/threats",),
    "audit": ("/logs",),
    "vulnerabilities": ("/vulnerabilities",),
    "notifications": (),  # Recipient-specific endpoint requires a user ID.
    "playbooks": ("/playbooks",),
    "reports": (
        "/reports/summary", "/reports/incidents", "/reports/assets",
        "/reports/threats", "/reports/vulnerabilities", "/reports/activity",
    ),
}


def _check(url, *, headers=None):
    try:
        response = requests.get(url, headers=headers, timeout=8)
        payload = response.json()
        return response.status_code == 200 and isinstance(payload, dict), response.status_code
    except (requests.RequestException, ValueError):
        return False, "unreachable"


def main():
    failures = 0
    for service in SERVICE_PORTS:
        ok, status = _check(f"{service_url(service)}/health")
        print(f"{'OK  ' if ok else 'FAIL'} {service:<17} /health ({status})")
        failures += not ok
    if failures:
        print("Start and configure all nine services before authenticated integration checks.")
        return 1

    username = input("Admin username: ").strip()
    password = getpass.getpass("Admin password: ")
    try:
        response = requests.post(
            f"{service_url('users')}/users/login",
            json={"username": username, "password": password}, timeout=8,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("user", {}).get("role") != "ADMIN" or not payload.get("access_token"):
            raise ValueError("Account is not an administrator.")
        token = payload["access_token"]
    except (requests.RequestException, ValueError, KeyError) as exc:
        print(f"Admin login failed: {type(exc).__name__}")
        return 1
    del password
    headers = {"Authorization": f"Bearer {token}"}

    for service, paths in READ_PATHS.items():
        for path in paths:
            ok, status = _check(f"{service_url(service)}{path}", headers=headers)
            print(f"{'OK  ' if ok else 'FAIL'} {service:<17} {path} ({status})")
            failures += not ok
    print("Read-only integration smoke check completed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
