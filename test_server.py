import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_jwks_excludes_expired_keys():
    response = client.get("/jwks")
    assert response.status_code == 200
    data = response.json()
    key_ids = [entry["kid"] for entry in data["keys"]]
    assert "kid-valid" in key_ids
    assert "kid-expired" not in key_ids

def test_auth_provides_active_token():
    response = client.post("/auth")
    assert response.status_code == 200
    payload = response.json()
    assert "token" in payload
    assert payload["kid"] == "kid-valid"

def test_auth_with_expired_flag():
    response = client.post("/auth?expired=1")
    assert response.status_code == 200
    payload = response.json()
    assert "token" in payload
    assert payload["kid"] == "kid-expired"
