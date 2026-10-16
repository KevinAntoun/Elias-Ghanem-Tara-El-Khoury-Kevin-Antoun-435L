"""Starter smoke tests. Add business/API/authorization tests per service."""

from importlib import import_module
import pytest
from shared.config import SERVICE_PORTS


@pytest.mark.parametrize("name", list(SERVICE_PORTS))
def test_service_health(name):
    app = import_module(f"services.{name}.app").app
    response = app.test_client().get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "service": name}


@pytest.mark.parametrize("name", list(SERVICE_PORTS))
def test_unknown_endpoint_responds_with_json(name):
    app = import_module(f"services.{name}.app").app
    response = app.test_client().get("/this-route-does-not-exist")
    assert response.status_code == 404
    assert response.get_json()["status"] == "error"
