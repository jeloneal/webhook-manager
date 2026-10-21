import http.server
import os
import sys
import tempfile
import threading

import pytest

# Konfiguration muss vor dem Import von app gesetzt sein (wird beim Import gelesen)
os.environ.update(
    WEBHOOK_PASSWORD='test-password-123',
    SECRET_KEY='k' * 32,
    DATABASE_PATH=os.path.join(tempfile.mkdtemp(), 'import.db'),
    COOKIE_SECURE='false',
)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module  # noqa: E402


@pytest.fixture
def a(monkeypatch, tmp_path):
    """Frische Datenbank und zurückgesetzter Zustand pro Test"""
    monkeypatch.setattr(app_module, 'DATABASE', str(tmp_path / 'test.db'))
    monkeypatch.setattr(app_module, 'ALLOW_PRIVATE_TARGETS', False)
    monkeypatch.setattr(app_module, 'ALLOWED_PRIVATE_HOSTS', set())
    monkeypatch.setattr(app_module, 'PASSWORD_HASH', '')
    monkeypatch.setattr(app_module.time, 'sleep', lambda s: None)  # Backoff überspringen
    app_module._failed_logins.clear()
    app_module.init_db()
    return app_module


@pytest.fixture
def client(a):
    return a.app.test_client()


@pytest.fixture
def auth(client):
    assert client.post('/api/login', json={'password': 'test-password-123'}).status_code == 200
    return client


class Target:
    """Lokaler HTTP-Server, der Requests aufzeichnet und konfigurierbar antwortet"""

    def __init__(self):
        self.requests = []
        self.responses = []  # Liste von Statuscodes; letzter wird wiederholt
        target = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(length) if length else b''
                target.requests.append({'method': self.command, 'path': self.path,
                                        'headers': {k.lower(): v for k, v in self.headers.items()}, 'body': body})
                status = target.responses.pop(0) if len(target.responses) > 1 else (target.responses[0] if target.responses else 204)
                self.send_response(status)
                self.end_headers()

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f'http://127.0.0.1:{self.port}/hook'


@pytest.fixture
def target(a, monkeypatch):
    monkeypatch.setattr(a, 'ALLOW_PRIVATE_TARGETS', True)
    t = Target()
    yield t
    t.server.shutdown()
