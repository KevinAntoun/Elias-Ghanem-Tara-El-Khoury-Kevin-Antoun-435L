"""Locations, ports and environment overrides for local development."""

import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")

SERVICE_PORTS = {
    "users": 5001,
    "assets": 5002,
    "incidents": 5003,
    "threats": 5004,
    "audit": 5005,
    "reports": 5006,
    "vulnerabilities": 5007,
    "notifications": 5008,
    "playbooks": 5009,
}


def service_port(name: str) -> int:
    """Return the development HTTP port for a known service."""
    return int(os.getenv(f"{name.upper()}_PORT", SERVICE_PORTS[name]))


def service_url(name: str) -> str:
    """Return a service's root URL for authenticated HTTP client calls."""
    default = f"http://127.0.0.1:{service_port(name)}"
    return os.getenv(f"{name.upper()}_SERVICE_URL", default).rstrip("/")


def database_path() -> Path:
    """Resolve the SQLite file relative to the project root by default."""
    configured = Path(os.getenv("DATABASE_PATH", "database/security_incidents.db"))
    return configured if configured.is_absolute() else PROJECT_ROOT / configured
