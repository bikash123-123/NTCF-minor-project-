import pytest
from backend.app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_auth_health(client):
    response = client.get("/auth/health")
    assert response.status_code == 200


def test_dashboard_health(client):
    response = client.get("/api/dashboard/health")
    assert response.status_code == 200


def test_detection_health(client):
    response = client.get("/api/detection/health")
    assert response.status_code == 200


def test_firewall_blocked(client):
    response = client.get("/api/firewall/blocked")
    assert response.status_code in (200, 500)


def test_threat_health(client):
    response = client.get("/api/threats/health")
    assert response.status_code == 200


def test_detection_invalid_json(client):
    response = client.post(
        "/api/detection/predict",
        json=None,
    )
    assert response.status_code in (400, 422, 500)


def test_firewall_block_missing_ip(client):
    response = client.post(
        "/api/firewall/block",
        json={},
    )
    assert response.status_code in (400, 422)


def test_firewall_unblock_missing_ip(client):
    response = client.post(
        "/api/firewall/unblock",
        json={},
    )
    assert response.status_code in (400, 422)


def test_unknown_route(client):
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404


def test_dashboard_statistics(client):
    response = client.get("/api/dashboard/statistics")
    assert response.status_code in (200, 500)


def test_threat_list(client):
    response = client.get("/api/threats")
    assert response.status_code in (200, 500)


def test_threat_invalid_index(client):
    response = client.get("/api/threats/not-a-number")
    assert response.status_code == 404
