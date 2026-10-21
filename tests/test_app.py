import json
import socket
import sqlite3

import pytest
from werkzeug.security import generate_password_hash

GOOD = {'name': 'Stack', 'url': 'https://8.8.8.8/api/stacks/webhooks/abc', 'method': 'POST'}


def create(client, **overrides):
    return client.post('/api/webhooks', json={**GOOD, **overrides})


# --- Konfiguration & Login ---------------------------------------------------

@pytest.mark.parametrize('password,key', [
    ('', 'k' * 32), ('admin123', 'k' * 32), ('ok-password', 'short'), ('ok-password', 'your-secret-key-change-me'),
])
def test_check_config_rejects_insecure_values(a, monkeypatch, password, key):
    monkeypatch.setattr(a, 'PASSWORD', password)
    monkeypatch.setattr(a, 'SECRET_KEY', key)
    with pytest.raises(RuntimeError):
        a.check_config()


def test_check_config_accepts_hash_and_rejects_bad_hash(a, monkeypatch):
    monkeypatch.setattr(a, 'PASSWORD', '')
    monkeypatch.setattr(a, 'PASSWORD_HASH', generate_password_hash('long-enough-pw'))
    a.check_config()
    monkeypatch.setattr(a, 'PASSWORD_HASH', 'plaintext')
    with pytest.raises(RuntimeError):
        a.check_config()


def test_login_with_password_hash(a, client, monkeypatch):
    monkeypatch.setattr(a, 'PASSWORD_HASH', generate_password_hash('hash-pw-12345'))
    assert client.post('/api/login', json={'password': 'test-password-123'}).status_code == 401
    assert client.post('/api/login', json={'password': 'hash-pw-12345'}).status_code == 200


def test_requires_auth(client):
    for method, path in [('get', '/api/webhooks'), ('post', '/api/webhooks'), ('get', '/api/history'),
                         ('get', '/api/export'), ('post', '/api/import'), ('post', '/api/webhooks/1/trigger'),
                         ('put', '/api/webhooks/1'), ('delete', '/api/webhooks/1')]:
        assert getattr(client, method)(path).status_code == 401, path


def test_login_rate_limit(client):
    for _ in range(5):
        assert client.post('/api/login', json={'password': 'wrong'}).status_code == 401
    assert client.post('/api/login', json={'password': 'test-password-123'}).status_code == 429


def test_login_rejects_bad_payload(client):
    assert client.post('/api/login', json={'password': 5}).status_code == 400
    assert client.post('/api/login', data='x').status_code == 400


def test_session_cookie_flags_and_headers(client):
    response = client.post('/api/login', json={'password': 'test-password-123'})
    cookie = response.headers['Set-Cookie']
    assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
    assert "default-src 'none'" in response.headers['Content-Security-Policy']
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert response.headers['Cache-Control'] == 'no-store'
    assert 'Access-Control-Allow-Origin' not in client.get('/api/status', headers={'Origin': 'http://evil'}).headers


def test_healthz_needs_no_auth(client, a, monkeypatch):
    assert client.get('/healthz').get_json() == {'status': 'ok'}
    monkeypatch.setattr(a, 'DATABASE', '/nonexistent-dir/x.db')
    assert client.get('/healthz').status_code == 503


# --- Validierung & SSRF ------------------------------------------------------

@pytest.mark.parametrize('url', [
    'http://127.0.0.1/', 'http://localhost:5000', 'http://169.254.169.254/latest', 'http://[::1]/',
    'http://10.0.0.1', 'http://192.168.1.1', 'http://[::ffff:127.0.0.1]/',
])
def test_private_targets_rejected(auth, url):
    response = create(auth, url=url)
    assert response.status_code == 400
    assert 'nicht öffentlich' in response.get_json()['error']


@pytest.mark.parametrize('url', ['file:///etc/passwd', 'ftp://8.8.8.8', 'http://user:pw@8.8.8.8/', 'http://', 'x' * 3000])
def test_invalid_urls_rejected(auth, url):
    assert create(auth, url=url).status_code == 400


@pytest.mark.parametrize('field,value', [
    ('method', 'TRACE'), ('method', '<img src=x>'), ('name', 5), ('url', 5), ('name', ' '), ('name', 'x' * 201),
    ('description', 'x' * 2001), ('timeout', 0), ('timeout', 61), ('timeout', 'abc'), ('retries', 4), ('retries', True),
    ('verify_tls', 'yes'), ('headers', ['a']), ('headers', {'Bad Name': 'x'}), ('headers', {'Host': 'evil'}),
    ('headers', {'X-A': 'line\r\nbreak'}), ('headers', {'X-A': '*' * 2049}),
    ('tags', ','.join(f't{i}' for i in range(11))), ('tags', ['x' * 31]), ('tags', [1]), ('body', 'x' * 20001),
])
def test_invalid_fields_rejected(auth, field, value):
    assert create(auth, **{field: value}).status_code == 400


def test_body_only_for_body_methods(auth):
    assert create(auth, method='GET', body='{}').status_code == 400
    assert create(auth, method='PUT', body='{}').status_code == 200


def test_allowed_private_host_is_permitted(auth, a, monkeypatch):
    assert create(auth, url='http://portainer.internal:9000/x').status_code == 400
    real = socket.getaddrinfo
    monkeypatch.setattr(socket, 'getaddrinfo', lambda h, *x, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.5', 9000))] if h == 'portainer.internal' else real(h, *x, **k))
    monkeypatch.setattr(a, 'ALLOWED_PRIVATE_HOSTS', {'portainer.internal'})
    assert create(auth, url='http://portainer.internal:9000/x').status_code == 200
    assert create(auth, url='http://other.internal:9000/x').status_code == 400


# --- CRUD, Header-Maskierung, Tags -------------------------------------------

def test_crud_roundtrip_with_defaults(auth):
    webhook_id = create(auth).get_json()['id']
    item = auth.get('/api/webhooks').get_json()[0]
    assert item['id'] == webhook_id
    assert (item['timeout'], item['retries'], item['verify_tls'], item['tags'], item['headers']) == (30, 0, True, [], {})
    assert item['last_triggered_at'] is None
    assert auth.put(f'/api/webhooks/{webhook_id}', json={**GOOD, 'name': 'Neu', 'method': 'put'}).status_code == 200
    assert auth.get('/api/webhooks').get_json()[0]['method'] == 'PUT'
    assert auth.put('/api/webhooks/999', json=GOOD).status_code == 404
    assert auth.delete(f'/api/webhooks/{webhook_id}').status_code == 200
    assert auth.delete(f'/api/webhooks/{webhook_id}').status_code == 404


def test_list_sorted_case_insensitive(auth):
    for name in ('beta', 'Alpha', 'gamma'):
        create(auth, name=name)
    assert [w['name'] for w in auth.get('/api/webhooks').get_json()] == ['Alpha', 'beta', 'gamma']


def test_headers_are_masked_and_kept_on_update(auth, a):
    webhook_id = create(auth, headers={'X-API-Key': 'supersecret'}).get_json()['id']
    assert auth.get('/api/webhooks').get_json()[0]['headers'] == {'X-API-Key': '********'}
    # Maske zurückschicken -> gespeicherter Wert bleibt
    assert auth.put(f'/api/webhooks/{webhook_id}', json={**GOOD, 'headers': {'x-api-key': '********', 'X-New': 'v'}}).status_code == 200
    stored = sqlite3.connect(a.DATABASE).execute('SELECT headers FROM webhooks').fetchone()[0]
    assert json.loads(stored) == {'x-api-key': 'supersecret', 'X-New': 'v'}
    # Maske für unbekannten Header ist ein Fehler
    assert auth.put(f'/api/webhooks/{webhook_id}', json={**GOOD, 'headers': {'X-Other': '********'}}).status_code == 400


def test_tags_normalized(auth):
    create(auth, tags=' prod, web ,Prod,, ')
    assert auth.get('/api/webhooks').get_json()[0]['tags'] == ['prod', 'web']


# --- Auslösen ----------------------------------------------------------------

def make(auth, target, **overrides):
    return create(auth, url=target.url, **overrides).get_json()['id']


def trigger(auth, webhook_id):
    response = auth.post(f'/api/webhooks/{webhook_id}/trigger')
    return response.status_code, response.get_json()


def test_trigger_default_payload_and_log(auth, target):
    webhook_id = make(auth, target)
    status, body = trigger(auth, webhook_id)
    assert status == 200 and body['success'] and body['status_code'] == 204 and body['attempts'] == 1
    assert 'response_text' not in body
    request = target.requests[0]
    assert request['method'] == 'POST' and request['headers']['content-type'] == 'application/json'
    assert json.loads(request['body'])['webhook_id'] == webhook_id
    item = auth.get('/api/webhooks').get_json()[0]
    assert item['last_success'] is True and item['last_status_code'] == 204
    history = auth.get(f'/api/webhooks/{webhook_id}/history').get_json()
    assert len(history) == 1 and history[0]['success'] and history[0]['webhook_name'] == 'Stack'


def test_trigger_custom_body_headers_and_methods(auth, target):
    webhook_id = make(auth, target, method='PATCH', headers={'X-API-Key': 'k1', 'Content-Type': 'text/plain'},
                      body='stack={{webhook_name}} id={{webhook_id}} "q"')
    assert trigger(auth, webhook_id)[0] == 200
    request = target.requests[0]
    assert request['method'] == 'PATCH'
    assert request['headers']['x-api-key'] == 'k1' and request['headers']['content-type'] == 'text/plain'
    assert request['body'].decode() == f'stack=Stack id={webhook_id} "q"'


def test_trigger_body_placeholders_are_json_escaped(auth, target):
    webhook_id = make(auth, target, name='a"b\\c', body='{"n": "{{webhook_name}}"}')
    trigger(auth, webhook_id)
    assert json.loads(target.requests[0]['body']) == {'n': 'a"b\\c'}


@pytest.mark.parametrize('method', ['GET', 'DELETE'])
def test_trigger_without_body_methods(auth, target, method):
    trigger(auth, make(auth, target, method=method))
    assert target.requests[0]['method'] == method and target.requests[0]['body'] == b''


def test_trigger_http_error_is_reported_and_logged(auth, target):
    target.responses = [404]
    webhook_id = make(auth, target)
    status, body = trigger(auth, webhook_id)
    assert status == 502 and not body['success'] and body['status_code'] == 404 and '404' in body['error']
    assert auth.get('/api/history').get_json()[0]['success'] is False


def test_trigger_does_not_follow_redirects(auth, target):
    target.responses = [302]
    status, body = trigger(auth, make(auth, target))
    assert status == 502 and 'Weiterleitung' in body['error'] and len(target.requests) == 1


def test_trigger_retries_on_5xx_then_succeeds(auth, target):
    target.responses = [500, 503, 204]
    status, body = trigger(auth, make(auth, target, retries=3))
    assert status == 200 and body['attempts'] == 3 and len(target.requests) == 3


def test_trigger_does_not_retry_4xx(auth, target):
    target.responses = [400]
    status, body = trigger(auth, make(auth, target, retries=3))
    assert status == 502 and body['attempts'] == 1


def test_trigger_connection_error_retries(auth, a, monkeypatch):
    monkeypatch.setattr(a, 'ALLOW_PRIVATE_TARGETS', True)
    s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
    webhook_id = create(auth, url=f'http://127.0.0.1:{port}/', retries=2).get_json()['id']
    status, body = trigger(auth, webhook_id)
    assert status == 502 and body['attempts'] == 3 and 'fehlgeschlagen' in body['error']


def test_trigger_timeout_is_504(auth, a, monkeypatch):
    import requests
    monkeypatch.setattr(a, 'ALLOW_PRIVATE_TARGETS', True)
    monkeypatch.setattr(requests.Session, 'request', lambda *args, **kw: (_ for _ in ()).throw(requests.exceptions.ReadTimeout()))
    webhook_id = create(auth, url='http://127.0.0.1:9/', timeout=2).get_json()['id']
    status, body = trigger(auth, webhook_id)
    assert status == 504 and 'Timeout nach 2' in body['error']


def test_trigger_unknown_webhook(auth):
    assert auth.post('/api/webhooks/999/trigger').status_code == 404


def test_trigger_rejects_private_target_stored_in_db(auth, a):
    webhook_id = create(auth).get_json()['id']
    with sqlite3.connect(a.DATABASE) as conn:
        conn.execute("UPDATE webhooks SET url = 'http://127.0.0.1:1/'")
    status, body = trigger(auth, webhook_id)
    assert status == 400 and 'nicht öffentlich' in body['error']


def test_connect_time_check_blocks_dns_rebinding(auth, a, monkeypatch):
    """Vorprüfung sieht eine öffentliche IP, der Verbindungsaufbau bekommt Loopback"""
    webhook_id = create(auth, url='http://8.8.8.8/x').get_json()['id']
    real = socket.getaddrinfo
    calls = []

    def fake(host, *args, **kw):
        if host == 'rebind.test':
            calls.append(1)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8' if len(calls) == 1 else '127.0.0.1', 80))]
        return real(host, *args, **kw)
    monkeypatch.setattr(socket, 'getaddrinfo', fake)
    with sqlite3.connect(a.DATABASE) as conn:
        conn.execute("UPDATE webhooks SET url = 'http://rebind.test/x'")
    status, body = trigger(auth, webhook_id)
    assert status == 400 and 'nicht öffentlich' in body['error'] and len(calls) == 2


def test_tls_verification_uses_hostname_not_pinned_ip(a, monkeypatch, tmp_path):
    import http.server, ssl, subprocess, threading
    key, cert = tmp_path / 'k.pem', tmp_path / 'c.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1',
                    '-subj', '/CN=webhook.test', '-addext', 'subjectAltName=DNS:webhook.test'], check=True, capture_output=True)

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b'ok')

        def log_message(self, *args):
            pass
    server = http.server.HTTPServer(('127.0.0.1', 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_port
    real = socket.getaddrinfo
    monkeypatch.setattr(socket, 'getaddrinfo', lambda h, *x, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port))] if h in ('webhook.test', 'wrong.test') else real(h, *x, **k))
    monkeypatch.setattr(a, 'is_public_ip', lambda ip: True)
    session = a.safe_session()
    try:
        assert session.get(f'https://webhook.test:{port}/', verify=str(cert), timeout=5).status_code == 200
        import requests
        with pytest.raises(requests.exceptions.SSLError):
            session.get(f'https://wrong.test:{port}/', verify=str(cert), timeout=5)
    finally:
        server.shutdown()


# --- Verlauf -----------------------------------------------------------------

def test_history_limit_clear_and_delete_with_webhook(auth, target):
    first, second = make(auth, target, name='a'), make(auth, target, name='b')
    trigger(auth, first); trigger(auth, first); trigger(auth, second)
    assert len(auth.get('/api/history').get_json()) == 3
    assert len(auth.get('/api/history?limit=2').get_json()) == 2
    assert auth.get('/api/history?limit=0').status_code == 400
    assert len(auth.get(f'/api/webhooks/{first}/history').get_json()) == 2
    auth.delete(f'/api/webhooks/{first}')
    assert len(auth.get('/api/history').get_json()) == 1
    auth.delete('/api/history')
    assert auth.get('/api/history').get_json() == []


def test_history_is_pruned(auth, target, a, monkeypatch):
    monkeypatch.setattr(a, 'LOG_KEEP', 3)
    webhook_id = make(auth, target)
    for _ in range(6):
        trigger(auth, webhook_id)
    assert len(auth.get('/api/history?limit=100').get_json()) == 3  # behält genau LOG_KEEP Einträge


# --- Export / Import ---------------------------------------------------------

def test_export_import_roundtrip(auth, a):
    create(auth, name='A', headers={'X-Key': 'secret'}, tags=['t1'], retries=2, timeout=10, body='{"a":1}', verify_tls=False)
    create(auth, name='B', method='GET')
    export = auth.get('/api/export')
    assert 'attachment' in export.headers['Content-Disposition']
    data = export.get_json()
    assert data['version'] == 1 and [w['name'] for w in data['webhooks']] == ['A', 'B']
    assert data['webhooks'][0]['headers'] == {'X-Key': 'secret'}  # Backup enthält Klartext
    # In frische DB importieren
    import os
    a.DATABASE = os.path.join(os.path.dirname(a.DATABASE), 'second.db')
    a.init_db()
    result = auth.post('/api/import', json=data).get_json()
    assert (result['imported'], result['skipped'], result['errors']) == (2, 0, [])
    again = auth.post('/api/import', json=data).get_json()
    assert (again['imported'], again['skipped']) == (0, 2)
    restored = auth.get('/api/export').get_json()['webhooks']
    assert restored == data['webhooks']


def test_import_reports_invalid_entries(auth):
    payload = {'webhooks': [GOOD, {**GOOD, 'url': 'http://127.0.0.1/'}, 'nonsense']}
    result = auth.post('/api/import', json=payload).get_json()
    assert result['imported'] == 1 and [e['index'] for e in result['errors']] == [1, 2]


def test_import_rejects_bad_format_and_size(auth, a, monkeypatch):
    assert auth.post('/api/import', json={'nope': 1}).status_code == 400
    monkeypatch.setattr(a, 'MAX_IMPORT', 1)
    assert auth.post('/api/import', json={'webhooks': [GOOD, GOOD]}).status_code == 400


def test_request_size_limit(auth):
    assert auth.post('/api/import', data=b'x' * (3 * 1024 * 1024), content_type='application/json').status_code == 413


# --- Migrationen -------------------------------------------------------------

def test_migration_from_v1_keeps_data(a, tmp_path, monkeypatch):
    path = str(tmp_path / 'old.db')
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE webhooks (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL, "
                 "method TEXT DEFAULT 'POST', description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
                 "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("INSERT INTO webhooks (name, url, method) VALUES ('alt', 'https://8.8.8.8/x', 'GET')")
    conn.commit(); conn.close()
    monkeypatch.setattr(a, 'DATABASE', path)
    a.init_db()
    a.init_db()  # idempotent
    with a.db() as c:
        assert c.execute('PRAGMA user_version').fetchone()[0] == len(a.MIGRATIONS)
        row = a.row_to_webhook(c.execute('SELECT * FROM webhooks').fetchone())
    assert (row['name'], row['timeout'], row['retries'], row['verify_tls'], row['tags']) == ('alt', 30, 0, True, [])


def test_failed_migration_rolls_back(a, tmp_path, monkeypatch):
    monkeypatch.setattr(a, 'DATABASE', str(tmp_path / 'broken.db'))

    def broken(conn):
        conn.execute('CREATE TABLE half_done (id INTEGER)')
        raise RuntimeError('boom')
    monkeypatch.setattr(a, 'MIGRATIONS', [a._migrate_1, broken])
    with pytest.raises(RuntimeError):
        a.init_db()
    with sqlite3.connect(a.DATABASE) as c:
        assert c.execute('PRAGMA user_version').fetchone()[0] == 1
        assert c.execute("SELECT name FROM sqlite_master WHERE name = 'half_done'").fetchone() is None


def test_connection_uses_the_checked_ip(auth, a, target, monkeypatch):
    """Die geprüfte IP wird für den Connect verwendet; eine spätere Neuauflösung darf nichts ändern"""
    monkeypatch.setattr(a, 'ALLOW_PRIVATE_TARGETS', False)
    monkeypatch.setattr(a, 'ALLOWED_PRIVATE_HOSTS', {'pin.test'})
    real = socket.getaddrinfo
    calls = []

    def fake(host, *args, **kw):
        if host == 'pin.test':
            calls.append(1)
            # Aufrufe 1 (Vorprüfung) und 2 (Connect-Prüfung) -> Zielserver, danach "umgebogen"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1' if len(calls) <= 2 else '192.0.2.1', target.port))]
        return real(host, *args, **kw)
    monkeypatch.setattr(socket, 'getaddrinfo', fake)
    webhook_id = create(auth, url=f'http://pin.test:{target.port}/hook').get_json()['id']
    calls.clear()
    status, _ = trigger(auth, webhook_id)
    assert status == 200 and len(target.requests) == 1


def test_frontend_assets_are_served_and_csp_compatible(client):
    page = client.get('/')
    html = page.get_data(as_text=True)
    assert page.status_code == 200
    assert '<script src="/static/theme.js">' in html and 'id="themeToggle"' in html
    assert 'name="color-scheme"' in html
    assert '<script>' not in html and ' onclick=' not in html and ' style="' not in html  # CSP: script-src 'self'
    for path in ('/static/theme.js', '/static/app.js', '/static/style.css', '/static/favicon.svg'):
        assert client.get(path).status_code == 200, path
    css = client.get('/static/style.css').get_data(as_text=True)
    assert 'prefers-color-scheme: dark' in css and ':root[data-theme="dark"]' in css
