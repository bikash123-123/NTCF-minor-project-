import pytest
from flask import Flask

from backend.routes.auth_routes import auth_bp


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.register_blueprint(auth_bp)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_auth_health(client):
    response = client.get("/auth/health")

    assert response.status_code == 200
    assert response.get_json()["module"] == "authentication"
    assert response.get_json()["status"] == "running"


def test_register_requires_json(client):
    response = client.post("/auth/register")

    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_register_invalid_json(client):
    response = client.post(
        "/auth/register",
        data="invalid",
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_login_requires_json(client):
    response = client.post("/auth/login")

    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_login_invalid_json(client):
    response = client.post(
        "/auth/login",
        data="invalid",
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_login_invalid_credentials(client):
    response = client.post(
        "/auth/login",
        json={
            "username": "nonexistent_user",
            "password": "wrong_password",
        },
    )

    assert response.status_code == 401
    assert response.get_json()["success"] is False
    assert response.get_json()["error"] == "Invalid credentials."


def test_protected_me_requires_authentication(client):
    response = client.get("/auth/me")

    assert response.status_code in (401, 403)


def test_protected_logout_requires_authentication(client):
    response = client.post("/auth/logout")

    assert response.status_code in (401, 403)