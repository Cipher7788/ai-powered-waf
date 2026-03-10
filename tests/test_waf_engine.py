"""Unit tests for WAFEngine detection methods."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from waf_engine import WAFEngine


@pytest.fixture
def engine():
    return WAFEngine()


class TestSQLInjection:
    def test_select_statement(self, engine):
        assert engine.detect_sql_injection({'query': 'SELECT * FROM users'}) is True

    def test_drop_table(self, engine):
        assert engine.detect_sql_injection({'query': 'DROP TABLE users'}) is True

    def test_union_attack(self, engine):
        assert engine.detect_sql_injection({'q': "1 UNION SELECT password FROM users"}) is True

    def test_comment_sequence(self, engine):
        assert engine.detect_sql_injection({'input': "admin'--"}) is True

    def test_clean_input(self, engine):
        assert engine.detect_sql_injection({'name': 'John Doe'}) is False

    def test_nested_dict(self, engine):
        assert engine.detect_sql_injection({'user': {'id': '1; DROP TABLE users'}}) is True


class TestXSS:
    def test_script_tag(self, engine):
        assert engine.detect_xss({'data': '<script>alert("xss")</script>'}) is True

    def test_javascript_protocol(self, engine):
        assert engine.detect_xss({'url': 'javascript:alert(1)'}) is True

    def test_event_handler(self, engine):
        assert engine.detect_xss({'input': '<img onerror=alert(1)>'}) is True

    def test_iframe(self, engine):
        assert engine.detect_xss({'html': '<iframe src="evil.com">'}) is True

    def test_clean_input(self, engine):
        assert engine.detect_xss({'comment': 'Hello, world!'}) is False

    def test_clean_html(self, engine):
        assert engine.detect_xss({'content': '<b>bold text</b>'}) is False


class TestPathTraversal:
    def test_dot_dot_slash(self, engine):
        assert engine.detect_path_traversal({'path': '../../../etc/passwd'}) is True

    def test_backslash_traversal(self, engine):
        assert engine.detect_path_traversal({'file': '..\\windows\\system32'}) is True

    def test_url_encoded(self, engine):
        assert engine.detect_path_traversal({'path': '%2e%2e%2fetc%2fpasswd'}) is True

    def test_clean_path(self, engine):
        assert engine.detect_path_traversal({'file': 'uploads/photo.jpg'}) is False


class TestCommandInjection:
    def test_semicolon(self, engine):
        assert engine.detect_command_injection({'cmd': 'ls; rm -rf /'}) is True

    def test_pipe(self, engine):
        assert engine.detect_command_injection({'input': 'cat /etc/passwd | grep root'}) is True

    def test_backtick(self, engine):
        assert engine.detect_command_injection({'data': '`whoami`'}) is True

    def test_ampersand(self, engine):
        assert engine.detect_command_injection({'q': 'echo hello & rm file'}) is True

    def test_clean_input(self, engine):
        assert engine.detect_command_injection({'message': 'Hello World'}) is False


class TestAnalyzeRequest:
    def test_returns_list(self, engine):
        result = engine.analyze_request({'q': 'normal text'})
        assert isinstance(result, list)

    def test_detects_sql_in_analyze(self, engine):
        result = engine.analyze_request({'q': 'SELECT * FROM users'})
        assert 'sql_injection' in result

    def test_empty_dict(self, engine):
        result = engine.analyze_request({})
        assert result == []

    def test_multiple_threats(self, engine):
        result = engine.analyze_request({'q': 'SELECT * FROM users', 'p': '../etc/passwd'})
        assert 'sql_injection' in result
        assert 'path_traversal' in result
