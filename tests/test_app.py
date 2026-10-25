import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

"""Integration tests for the Flask WAF API."""
import json
import pytest
from app import app, rate_limiter


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("WAF_ADMIN_TOKEN", "test-admin-token")
    app.config["TESTING"] = True
    app.config["WAF_SETTINGS"] = {
        "rate_limit_max_requests": 1000,
        "rate_limit_window_seconds": 60,
        "enabled_rules": ["sql_injection", "xss", "path_traversal", "command_injection"],
    }
    rate_limiter.configure(max_requests=1000, window_seconds=60)
    rate_limiter._clients.clear()
    with app.test_client() as test_client:
        yield test_client


def post_json(client, path, data, **kwargs):
    return client.post(path, data=json.dumps(data), content_type="application/json", **kwargs)


def test_status_endpoint(client):
    response = client.get("/waf/status")
    assert response.status_code == 200
    assert response.get_json()["status"] == "WAF is operational"


@pytest.mark.parametrize(("payload", "expected"), [
    ({"message": "Hello world"}, False),
    ({"query": "SELECT * FROM users"}, True),
    ({"input": '<script>alert("xss")</script>'}, True),
    ({"file": "../../../etc/passwd"}, True),
    ({"cmd": "hello; curl https://example.invalid"}, True),
    ({"nested": [{"value": "%253Cscript%253E"}]}, True),
])
def test_analyze_detection(client, payload, expected):
    response = post_json(client, "/waf/analyze", payload)
    assert response.status_code == 200
    result = response.get_json()
    assert result["threat_detected"] is expected
    assert isinstance(result["threats"], list)
    assert "ai_predictions" in result


def test_invalid_json_returns_400(client):
    response = client.post("/waf/analyze", data="not json", content_type="application/json")
    assert response.status_code == 400


def test_missing_json_content_type_returns_400(client):
    response = client.post("/waf/analyze", data='{"hello":"world"}')
    assert response.status_code == 400


def test_admin_endpoints_require_authentication(client):
    assert client.get("/waf/logs").status_code == 401
    assert client.get("/waf/logs", headers={"X-Admin-Token": "wrong"}).status_code == 401
    assert client.post("/waf/config", json={"rate_limit_max_requests": 200}).status_code == 401


def test_config_updates_are_applied(client):
    response = post_json(
        client, "/waf/config",
        {"rate_limit_max_requests": 200, "enabled_rules": ["xss"]},
        headers={"X-Admin-Token": "test-admin-token"},
    )
    assert response.status_code == 200
    assert response.get_json()["config"]["rate_limit_max_requests"] == 200
    assert app.config["WAF_SETTINGS"]["enabled_rules"] == ["xss"]
    assert rate_limiter.max_requests == 200


@pytest.mark.parametrize("config", [
    {"rate_limit_max_requests": 0},
    {"rate_limit_window_seconds": -1},
    {"enabled_rules": ["not_a_rule"]},
    {"unexpected": True},
])
def test_invalid_config_is_rejected(client, config):
    response = post_json(client, "/waf/config", config, headers={"X-Admin-Token": "test-admin-token"})
    assert response.status_code == 400


def test_disabled_rule_is_not_run(client):
    app.config["WAF_SETTINGS"]["enabled_rules"] = ["xss"]
    result = post_json(client, "/waf/analyze", {"query": "SELECT * FROM users"}).get_json()
    assert result["threat_detected"] is False


def test_request_body_limit(client):
    response = client.post(
        "/waf/analyze", data='{"x":"' + ("a" * (1024 * 1024 + 10)) + '"}',
        content_type="application/json",
    )
    assert response.status_code == 413
