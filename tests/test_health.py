#
# Tiny test to pass CI, just checks the health endpoint to ensure API running.
#
from fastapi.testclient import TestClient

from app.main import app


def test_healthz():
    client = TestClient(app)
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "db": "up"}