"""Check every running service's health endpoint from another terminal."""

import requests
from shared.config import SERVICE_PORTS, service_url


def main() -> int:
    failed = False
    for service in SERVICE_PORTS:
        url = f"{service_url(service)}/health"
        try:
            response = requests.get(url, timeout=2)
            response.raise_for_status()
            data = response.json()
            ok = data.get("service") == service and data.get("status") == "ok"
        except (requests.exceptions.RequestException, ValueError):
            ok = False
        print(f"{'OK ' if ok else 'FAIL'} {service:<17} {url}")
        failed = failed or not ok
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
