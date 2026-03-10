"""Integration tests for the Flask WAF application."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import json
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestWafStatus:
    def test_status_endpoint(self, client):
        response = client.get('/waf/status')
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'WAF is operational'


class TestWafAnalyze:
    def test_clean_request(self, client):
        response = client.post(
            '/waf/analyze',
            data=json.dumps({'message': 'Hello world'}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert 'threat_detected' in data
        assert data['threat_detected'] is False

    def test_sql_injection_detected(self, client):
        response = client.post(
            '/waf/analyze',
            data=json.dumps({'query': 'SELECT * FROM users'}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['threat_detected'] is True
        assert 'sql_injection' in data['threats']

    def test_xss_detected(self, client):
        response = client.post(
            '/waf/analyze',
            data=json.dumps({'input': '<script>alert("xss")</script>'}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['threat_detected'] is True
        assert 'xss' in data['threats']

    def test_path_traversal_detected(self, client):
        response = client.post(
            '/waf/analyze',
            data=json.dumps({'file': '../../../etc/passwd'}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['threat_detected'] is True
        assert 'path_traversal' in data['threats']

    def test_invalid_json_returns_400(self, client):
        response = client.post(
            '/waf/analyze',
            data='not json',
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_response_has_required_fields(self, client):
        response = client.post(
            '/waf/analyze',
            data=json.dumps({'data': 'test'}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert 'threat_detected' in data
        assert 'threats' in data


class TestWafConfig:
    def test_get_config(self, client):
        response = client.get('/waf/config')
        assert response.status_code == 200

    def test_post_config(self, client):
        response = client.post(
            '/waf/config',
            data=json.dumps({'rate_limit': 200}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Config updated'


class TestWafLogs:
    def test_logs_endpoint(self, client):
        response = client.get('/waf/logs')
        assert response.status_code == 200
        data = response.get_json()
        assert 'logs' in data
