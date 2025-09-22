import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_jwks_only_unexpired():
    res = client.get("/jwks")
    assert res.status_code == 200
    body = res.json()
    kids = [k["kid"] for k in body["keys"]]
    assert "kid-valid" in kids
    assert "kid-expired" not in kids

def test_auth_returns_token():
    res = client.post("/auth")
    assert res.status_code == 200
    body = res.json()
    assert "token" in body
    assert body["kid"] == "kid-valid"

def test_auth_expired_key():
    res = client.post("/auth?expired=1")
    assert res.status_code == 200
    body = res.json()
    assert "token" in body
    assert body["kid"] == "kid-expired"
