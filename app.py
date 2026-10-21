#!/usr/bin/env python3
"""
Webhook Manager - Sichere Webanwendung zum Verwalten und Auslösen von Webhooks
"""

import os
import re
import sys
import json
import hmac
import time
import socket
import sqlite3
import ipaddress
import threading
import warnings
import logging
from contextlib import contextmanager
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from functools import wraps
import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.exceptions import NameResolutionError, NewConnectionError, InsecureRequestWarning
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, request, jsonify, session, send_from_directory, Response


# --- Konfiguration -----------------------------------------------------------

PASSWORD = os.environ.get('WEBHOOK_PASSWORD', '')
# Alternative zum Klartext-Passwort: Hash erzeugen mit `python app.py --hash-password`
PASSWORD_HASH = os.environ.get('WEBHOOK_PASSWORD_HASH', '')
SECRET_KEY = os.environ.get('SECRET_KEY', '')
DATABASE = os.environ.get('DATABASE_PATH', 'webhooks.db')
PORT = int(os.environ.get('PORT', 5000))
# Session-Cookie nur über HTTPS senden; für reinen HTTP-Betrieb (z.B. localhost) auf "false" setzen
COOKIE_SECURE = os.environ.get('COOKIE_SECURE', 'true').lower() != 'false'
# Standardmäßig sind Ziele in privaten/internen Netzen gesperrt (SSRF-Schutz)
ALLOW_PRIVATE_TARGETS = os.environ.get('ALLOW_PRIVATE_TARGETS', 'false').lower() == 'true'
# Gezielte Ausnahme: diese Hostnamen/IPs dürfen auch auf private Adressen zeigen (z.B. Portainer)
ALLOWED_PRIVATE_HOSTS = {
    h.strip().lower().rstrip('.')
    for h in os.environ.get('ALLOWED_PRIVATE_HOSTS', '').split(',') if h.strip()
}
# Anzahl vorgeschalteter Reverse-Proxys (z.B. 1 bei Traefik), damit die echte Client-IP gilt
TRUSTED_PROXIES = int(os.environ.get('TRUSTED_PROXIES', 0))
LOG_FORMAT = os.environ.get('LOG_FORMAT', 'text').lower()

ALLOWED_METHODS = ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')
BODY_METHODS = ('POST', 'PUT', 'PATCH')
MAX_NAME_LEN = 200
MAX_URL_LEN = 2048
MAX_DESCRIPTION_LEN = 2000
MAX_BODY_LEN = 20000
MAX_HEADERS = 20
MAX_HEADER_VALUE_LEN = 2048
MAX_TAGS = 10
MAX_TAG_LEN = 30
MIN_TIMEOUT, MAX_TIMEOUT, DEFAULT_TIMEOUT = 1, 60, 30
MAX_RETRIES = 3
MAX_IMPORT = 500
LOG_KEEP = 2000
HEADER_MASK = '********'

HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
FORBIDDEN_HEADERS = {'host', 'content-length', 'transfer-encoding', 'connection', 'upgrade', 'te', 'trailer'}

# Bekannte Beispielwerte, mit denen die App nicht starten darf
INSECURE_VALUES = {'', 'admin123', 'your-secret-key-change-me', 'changeme', 'password'}

# Brute-Force-Schutz für den Login
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
_failed_logins = {}
_failed_logins_lock = threading.Lock()

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


# --- Logging -----------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            'time': datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        if record.exc_info:
            payload['exception'] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


_handler = logging.StreamHandler()
if LOG_FORMAT == 'json':
    _handler.setFormatter(JsonFormatter())
else:
    _handler.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))
logging.basicConfig(level=logging.INFO, handlers=[_handler])
logger = logging.getLogger(__name__)


def check_config():
    """Bricht ab, wenn unsichere Standardwerte konfiguriert sind"""
    if PASSWORD_HASH:
        if not PASSWORD_HASH.startswith(('scrypt:', 'pbkdf2:')):
            raise RuntimeError('WEBHOOK_PASSWORD_HASH hat kein gültiges Format (python app.py --hash-password)')
    elif PASSWORD in INSECURE_VALUES:
        raise RuntimeError('WEBHOOK_PASSWORD (oder WEBHOOK_PASSWORD_HASH) muss gesetzt und darf kein Beispielwert sein')
    if SECRET_KEY in INSECURE_VALUES or len(SECRET_KEY) < 16:
        raise RuntimeError('SECRET_KEY muss gesetzt sein (mindestens 16 Zeichen, kein Beispielwert)')


def verify_password(candidate):
    if PASSWORD_HASH:
        return check_password_hash(PASSWORD_HASH, candidate)
    return hmac.compare_digest(candidate.encode('utf-8'), PASSWORD.encode('utf-8'))


app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)
if TRUSTED_PROXIES > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXIES, x_proto=TRUSTED_PROXIES)

# Hinweis: Das Frontend wird vom selben Server ausgeliefert, daher ist kein CORS nötig.


# --- Login-Rate-Limit --------------------------------------------------------

def is_login_blocked(ip):
    now = time.time()
    with _failed_logins_lock:
        attempts = [t for t in _failed_logins.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
        if attempts:
            _failed_logins[ip] = attempts
        else:
            _failed_logins.pop(ip, None)
        return len(attempts) >= MAX_LOGIN_ATTEMPTS


def register_failed_login(ip):
    with _failed_logins_lock:
        _failed_logins.setdefault(ip, []).append(time.time())


# --- SSRF-Schutz -------------------------------------------------------------

def is_public_ip(address):
    ip = ipaddress.ip_address(address.split('%')[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global


def resolve_public_ip(host, port):
    """Löst einen Host auf und gibt eine öffentliche IP zurück (sonst ValueError).

    Wird direkt beim Verbindungsaufbau verwendet: die geprüfte IP ist exakt die,
    mit der verbunden wird. Das schließt DNS-Rebinding zwischen Prüfung und
    Request aus. Hosts aus ALLOWED_PRIVATE_HOSTS sind ausdrücklich freigegeben.
    """
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    addresses = [info[4][0] for info in infos]
    if not addresses:
        raise ValueError('Host konnte nicht aufgelöst werden')
    if host.lower().rstrip('.') in ALLOWED_PRIVATE_HOSTS:
        return addresses[0]
    if not all(is_public_ip(a) for a in addresses):
        raise ValueError('Ziel liegt in einem nicht öffentlichen Netzwerk')
    return addresses[0]


class _PinnedConnectionMixin:
    def _new_conn(self):
        if ALLOW_PRIVATE_TARGETS:
            return super()._new_conn()
        # In urllib3 ist host an _dns_host gekoppelt (Zertifikatsprüfung/SNI).
        # Die geprüfte IP gilt deshalb nur für den Socket-Connect, danach wird
        # der Hostname wiederhergestellt.
        hostname = self._dns_host
        try:
            pinned_ip = resolve_public_ip(hostname, self.port)
        except socket.gaierror as e:
            raise NameResolutionError(hostname, self, e) from e
        except ValueError as e:
            raise NewConnectionError(self, str(e)) from e
        self._dns_host = pinned_ip
        try:
            return super()._new_conn()
        finally:
            self._dns_host = hostname


class _PinnedHTTPConnection(_PinnedConnectionMixin, HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinnedConnectionMixin, HTTPSConnection):
    pass


class _PinnedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class _PinnedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            'http': _PinnedHTTPPool,
            'https': _PinnedHTTPSPool,
        }


def safe_session():
    """requests-Session, die nur zu geprüften öffentlichen IPs verbindet"""
    session_ = requests.Session()
    session_.trust_env = False  # keine Proxy-Umgebungsvariablen (würden die Prüfung umgehen)
    adapter = _PinnedAdapter()
    session_.mount('http://', adapter)
    session_.mount('https://', adapter)
    return session_


def validate_target_url(url):
    """Prüft eine Webhook-URL. Gibt eine Fehlermeldung zurück oder None, wenn gültig.

    Frühe Prüfung für sofortiges Feedback. Maßgeblich ist die Prüfung beim
    Verbindungsaufbau (siehe safe_session), die auch DNS-Rebinding abdeckt.
    """
    if len(url) > MAX_URL_LEN:
        return 'URL ist zu lang'
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return 'Ungültige URL'
    if parsed.scheme not in ('http', 'https') or not hostname:
        return 'URL muss mit http:// oder https:// beginnen und einen Host enthalten'
    if parsed.username or parsed.password:
        return 'Zugangsdaten in der URL sind nicht erlaubt'
    if ALLOW_PRIVATE_TARGETS:
        return None
    try:
        resolve_public_ip(hostname, port or (443 if parsed.scheme == 'https' else 80))
    except socket.gaierror:
        return 'Host konnte nicht aufgelöst werden'
    except ValueError as e:
        return str(e)
    return None


# --- Validierung -------------------------------------------------------------

def parse_headers(raw, existing=None):
    """Validiert Header. Der Platzhalter HEADER_MASK behält den gespeicherten Wert."""
    if raw in (None, ''):
        return {}, None
    if not isinstance(raw, dict):
        return None, 'Header müssen ein Objekt sein'
    if len(raw) > MAX_HEADERS:
        return None, f'Maximal {MAX_HEADERS} Header erlaubt'
    existing_lower = {k.lower(): v for k, v in (existing or {}).items()}
    headers = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not isinstance(value, str):
            return None, 'Header-Namen und -Werte müssen Text sein'
        name, value = name.strip(), value.strip()
        if not HEADER_NAME_RE.match(name):
            return None, f'Ungültiger Header-Name: {name[:30]}'
        if name.lower() in FORBIDDEN_HEADERS:
            return None, f'Header {name} ist nicht erlaubt'
        if name.lower() in {k.lower() for k in headers}:
            return None, f'Header {name} ist doppelt'
        if value == HEADER_MASK:
            if name.lower() not in existing_lower:
                return None, f'Header {name}: bitte einen Wert angeben'
            value = existing_lower[name.lower()]
        if len(value) > MAX_HEADER_VALUE_LEN or re.search(r'[\x00-\x08\x0a-\x1f\x7f]', value):
            return None, f'Ungültiger Wert für Header {name}'
        headers[name] = value
    return headers, None


def parse_tags(raw):
    if raw in (None, ''):
        return [], None
    if isinstance(raw, str):
        raw = raw.split(',')
    if not isinstance(raw, list) or not all(isinstance(t, str) for t in raw):
        return None, 'Tags müssen eine Liste von Texten sein'
    tags, seen = [], set()
    for tag in raw:
        tag = tag.strip()
        if not tag or tag.lower() in seen:
            continue
        if len(tag) > MAX_TAG_LEN:
            return None, f'Tag ist zu lang (max. {MAX_TAG_LEN} Zeichen)'
        seen.add(tag.lower())
        tags.append(tag)
    if len(tags) > MAX_TAGS:
        return None, f'Maximal {MAX_TAGS} Tags erlaubt'
    return tags, None


def parse_int(value, default, low, high, label):
    if value in (None, ''):
        return default, None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None, f'{label} muss eine Zahl sein'
    try:
        number = int(value)
    except ValueError:
        return None, f'{label} muss eine Zahl sein'
    if not low <= number <= high:
        return None, f'{label} muss zwischen {low} und {high} liegen'
    return number, None


def parse_webhook_payload(data, existing_headers=None):
    """Validiert Eingabedaten. Gibt (werte-dict, fehler) zurück."""
    if not isinstance(data, dict):
        return None, 'Ungültige Anfrage'
    name, url = data.get('name'), data.get('url')
    method = data.get('method') or 'POST'
    description = data.get('description') or ''
    body = data.get('body') or ''
    if not all(isinstance(v, str) for v in (name, url, method, description, body)):
        return None, 'Ungültige Feldtypen'
    name, url, description = name.strip(), url.strip(), description.strip()
    method = method.strip().upper()
    if not name or not url:
        return None, 'Name und URL sind erforderlich'
    if len(name) > MAX_NAME_LEN or len(description) > MAX_DESCRIPTION_LEN:
        return None, 'Name oder Beschreibung ist zu lang'
    if method not in ALLOWED_METHODS:
        return None, 'Methode muss ' + ', '.join(ALLOWED_METHODS) + ' sein'
    if len(body) > MAX_BODY_LEN:
        return None, f'Body ist zu lang (max. {MAX_BODY_LEN} Zeichen)'
    if body.strip() and method not in BODY_METHODS:
        return None, 'Ein Body ist nur bei POST, PUT und PATCH möglich'
    verify_tls = data.get('verify_tls', True)
    if not isinstance(verify_tls, bool):
        return None, 'verify_tls muss true oder false sein'
    timeout, error = parse_int(data.get('timeout'), DEFAULT_TIMEOUT, MIN_TIMEOUT, MAX_TIMEOUT, 'Timeout')
    if error:
        return None, error
    retries, error = parse_int(data.get('retries'), 0, 0, MAX_RETRIES, 'Wiederholungen')
    if error:
        return None, error
    headers, error = parse_headers(data.get('headers'), existing_headers)
    if error:
        return None, error
    tags, error = parse_tags(data.get('tags'))
    if error:
        return None, error
    error = validate_target_url(url)
    if error:
        return None, error
    return {
        'name': name, 'url': url, 'method': method, 'description': description,
        'headers': headers, 'body': body if body.strip() else '',
        'timeout': timeout, 'retries': retries, 'verify_tls': verify_tls, 'tags': tags,
    }, None


# --- Datenbank ---------------------------------------------------------------

@contextmanager
def db():
    """SQLite-Verbindung, die immer geschlossen wird (Commit bei Erfolg, Rollback bei Fehler)"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def _migrate_1(conn):
    conn.execute('''
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            method TEXT DEFAULT 'POST',
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')


def _migrate_2(conn):
    conn.execute("ALTER TABLE webhooks ADD COLUMN headers TEXT NOT NULL DEFAULT '{}'")
    conn.execute("ALTER TABLE webhooks ADD COLUMN body TEXT NOT NULL DEFAULT ''")
    conn.execute(f"ALTER TABLE webhooks ADD COLUMN timeout INTEGER NOT NULL DEFAULT {DEFAULT_TIMEOUT}")
    conn.execute("ALTER TABLE webhooks ADD COLUMN retries INTEGER NOT NULL DEFAULT 0")
    conn.execute("ALTER TABLE webhooks ADD COLUMN verify_tls INTEGER NOT NULL DEFAULT 1")
    conn.execute("ALTER TABLE webhooks ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'")
    conn.execute('''
        CREATE TABLE trigger_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            webhook_id INTEGER NOT NULL,
            webhook_name TEXT NOT NULL,
            triggered_at TEXT NOT NULL,
            success INTEGER NOT NULL,
            status_code INTEGER,
            duration_ms INTEGER,
            attempts INTEGER NOT NULL DEFAULT 1,
            error TEXT
        )
    ''')
    conn.execute('CREATE INDEX idx_trigger_log_webhook ON trigger_log (webhook_id, id)')


# Neue Schema-Änderungen werden hier hinten angehängt (PRAGMA user_version = Index + 1)
MIGRATIONS = [_migrate_1, _migrate_2]


def init_db():
    """Legt die Datenbank an bzw. führt ausstehende Migrationen aus"""
    db_dir = os.path.dirname(DATABASE)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f'Datenbank-Verzeichnis erstellt: {db_dir}')
        except Exception as e:
            logger.error(f'Fehler beim Erstellen des DB-Verzeichnisses: {e}')
            raise

    try:
        with db() as conn:
            version = conn.execute('PRAGMA user_version').fetchone()[0]
            for index in range(version, len(MIGRATIONS)):
                conn.execute('BEGIN')  # DDL ist sonst nicht atomar (sqlite3 beginnt nur bei DML eine Transaktion)
                MIGRATIONS[index](conn)
                conn.execute(f'PRAGMA user_version = {index + 1}')
                conn.commit()
                logger.info(f'Datenbank-Migration {index + 1} angewendet')
        logger.info(f'Datenbank erfolgreich initialisiert: {DATABASE}')
    except Exception as e:
        logger.error(f'Fehler beim Initialisieren der Datenbank: {e}')
        raise


WEBHOOK_SELECT = '''
    SELECT w.*,
        (SELECT triggered_at FROM trigger_log l WHERE l.webhook_id = w.id ORDER BY l.id DESC LIMIT 1) AS last_triggered_at,
        (SELECT success FROM trigger_log l WHERE l.webhook_id = w.id ORDER BY l.id DESC LIMIT 1) AS last_success,
        (SELECT status_code FROM trigger_log l WHERE l.webhook_id = w.id ORDER BY l.id DESC LIMIT 1) AS last_status_code
    FROM webhooks w
'''


def row_to_webhook(row, mask=True):
    """Datenbankzeile -> API-Objekt. Header-Werte werden standardmäßig maskiert."""
    headers = json.loads(row['headers'] or '{}')
    if mask:
        headers = {name: HEADER_MASK for name in headers}
    webhook = {
        'id': row['id'],
        'name': row['name'],
        'url': row['url'],
        'method': row['method'],
        'description': row['description'] or '',
        'headers': headers,
        'body': row['body'],
        'timeout': row['timeout'],
        'retries': row['retries'],
        'verify_tls': bool(row['verify_tls']),
        'tags': json.loads(row['tags'] or '[]'),
        'created_at': row['created_at'],
    }
    keys = row.keys()
    if 'last_triggered_at' in keys:
        webhook['last_triggered_at'] = row['last_triggered_at']
        webhook['last_success'] = None if row['last_success'] is None else bool(row['last_success'])
        webhook['last_status_code'] = row['last_status_code']
    return webhook


def webhook_db_values(values):
    return (
        values['name'], values['url'], values['method'], values['description'],
        json.dumps(values['headers']), values['body'], values['timeout'],
        values['retries'], int(values['verify_tls']), json.dumps(values['tags']),
    )


INSERT_SQL = '''
    INSERT INTO webhooks (name, url, method, description, headers, body, timeout, retries, verify_tls, tags)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
'''


# --- Authentifizierung -------------------------------------------------------

def require_auth(f):
    """Decorator für Authentifizierung"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return jsonify({'error': 'Nicht authentifiziert'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    """Serve the main HTML file"""
    return send_from_directory('.', 'index.html')


@app.route('/healthz', methods=['GET'])
def healthz():
    """Liveness/Readiness ohne Authentifizierung (prüft die Datenbank)"""
    try:
        with db() as conn:
            conn.execute('SELECT 1').fetchone()
    except Exception as e:
        logger.error(f'Healthcheck fehlgeschlagen: {e}')
        return jsonify({'status': 'error'}), 503
    return jsonify({'status': 'ok'})


@app.route('/api/login', methods=['POST'])
def login():
    """Login-Endpoint"""
    ip = request.remote_addr or 'unknown'
    if is_login_blocked(ip):
        logger.warning(f'Login gesperrt (zu viele Versuche): {ip}')
        return jsonify({'error': 'Zu viele Fehlversuche. Bitte später erneut versuchen.'}), 429

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get('password'), str):
        return jsonify({'error': 'Passwort erforderlich'}), 400

    if verify_password(data['password']):
        session.clear()
        session['authenticated'] = True
        session.permanent = True
        logger.info(f'Erfolgreicher Login von {ip}')
        return jsonify({'success': True})
    register_failed_login(ip)
    logger.warning(f'Fehlgeschlagener Login-Versuch von {ip}')
    return jsonify({'error': 'Falsches Passwort'}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout-Endpoint"""
    session.clear()
    return jsonify({'success': True})


@app.route('/api/status', methods=['GET'])
def status():
    """Status der Authentifizierung prüfen"""
    return jsonify({'authenticated': session.get('authenticated', False)})


# --- Webhook-CRUD ------------------------------------------------------------

@app.route('/api/webhooks', methods=['GET'])
@require_auth
def get_webhooks():
    """Alle Webhooks abrufen"""
    try:
        with db() as conn:
            rows = conn.execute(WEBHOOK_SELECT + ' ORDER BY w.name COLLATE NOCASE').fetchall()
        return jsonify([row_to_webhook(row) for row in rows])
    except Exception as e:
        logger.error(f'Fehler beim Laden der Webhooks: {e}')
        return jsonify({'error': 'Fehler beim Laden der Webhooks'}), 500


@app.route('/api/webhooks', methods=['POST'])
@require_auth
def create_webhook():
    """Neuen Webhook erstellen"""
    values, error = parse_webhook_payload(request.get_json(silent=True))
    if error:
        return jsonify({'error': error}), 400

    try:
        with db() as conn:
            webhook_id = conn.execute(INSERT_SQL, webhook_db_values(values)).lastrowid
        logger.info(f'Webhook erstellt: {values["name"]!r} (ID: {webhook_id})')
        return jsonify({'id': webhook_id, 'success': True})
    except Exception as e:
        logger.error(f'Fehler beim Erstellen des Webhooks: {e}')
        return jsonify({'error': 'Webhook konnte nicht erstellt werden'}), 500


@app.route('/api/webhooks/<int:webhook_id>', methods=['PUT'])
@require_auth
def update_webhook(webhook_id):
    """Webhook aktualisieren"""
    data = request.get_json(silent=True)
    try:
        with db() as conn:
            row = conn.execute('SELECT headers FROM webhooks WHERE id = ?', (webhook_id,)).fetchone()
            if row is None:
                return jsonify({'error': 'Webhook nicht gefunden'}), 404
            values, error = parse_webhook_payload(data, json.loads(row['headers'] or '{}'))
            if error:
                return jsonify({'error': error}), 400
            conn.execute('''
                UPDATE webhooks
                SET name = ?, url = ?, method = ?, description = ?, headers = ?, body = ?,
                    timeout = ?, retries = ?, verify_tls = ?, tags = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', webhook_db_values(values) + (webhook_id,))
        logger.info(f'Webhook aktualisiert: ID {webhook_id}')
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Fehler beim Aktualisieren des Webhooks: {e}')
        return jsonify({'error': 'Webhook konnte nicht aktualisiert werden'}), 500


@app.route('/api/webhooks/<int:webhook_id>', methods=['DELETE'])
@require_auth
def delete_webhook(webhook_id):
    """Webhook löschen (inklusive Verlauf)"""
    try:
        with db() as conn:
            found = conn.execute('DELETE FROM webhooks WHERE id = ?', (webhook_id,)).rowcount > 0
            if found:
                conn.execute('DELETE FROM trigger_log WHERE webhook_id = ?', (webhook_id,))
        if not found:
            return jsonify({'error': 'Webhook nicht gefunden'}), 404
        logger.info(f'Webhook gelöscht: ID {webhook_id}')
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Fehler beim Löschen des Webhooks: {e}')
        return jsonify({'error': 'Webhook konnte nicht gelöscht werden'}), 500


# --- Auslösen ----------------------------------------------------------------

def render_body(template, webhook, timestamp):
    """Ersetzt Platzhalter im Body; Werte werden JSON-escaped"""
    def esc(value):
        return json.dumps(str(value), ensure_ascii=False)[1:-1]
    return (template
            .replace('{{timestamp}}', esc(timestamp))
            .replace('{{webhook_id}}', esc(webhook['id']))
            .replace('{{webhook_name}}', esc(webhook['name'])))


def execute_webhook(webhook):
    """Sendet den Request (mit Wiederholungen). Gibt ein Ergebnis-Dict zurück.

    kind: ok | target_rejected | timeout | connection | tls | http_error
    """
    result = {'success': False, 'status_code': None, 'duration_ms': 0, 'attempts': 0,
              'error': None, 'kind': None}

    error = validate_target_url(webhook['url'])
    if error:
        result.update(error=error, kind='target_rejected')
        return result

    timestamp = datetime.now(timezone.utc).isoformat()
    method = webhook['method'].upper()
    headers = {'User-Agent': 'Webhook-Manager/1.0'}
    headers.update(webhook['headers'])
    header_names = {name.lower() for name in headers}

    kwargs = {}
    if method in BODY_METHODS:
        if webhook['body'].strip():
            kwargs['data'] = render_body(webhook['body'], webhook, timestamp).encode('utf-8')
        else:
            kwargs['data'] = json.dumps({
                'timestamp': timestamp,
                'source': 'webhook-manager',
                'webhook_id': webhook['id'],
                'webhook_name': webhook['name'],
            }).encode('utf-8')
        if 'content-type' not in header_names:
            headers['Content-Type'] = 'application/json'

    http = safe_session()
    started = time.monotonic()
    attempts = webhook['retries'] + 1
    for attempt in range(1, attempts + 1):
        result['attempts'] = attempt
        retryable = False
        try:
            with warnings.catch_warnings():
                if not webhook['verify_tls']:
                    warnings.simplefilter('ignore', InsecureRequestWarning)
                response = http.request(
                    method, webhook['url'], headers=headers, timeout=webhook['timeout'],
                    allow_redirects=False, verify=webhook['verify_tls'], **kwargs)
            result['status_code'] = response.status_code
            if 200 <= response.status_code < 300:
                result.update(success=True, kind='ok', error=None)
                break
            if 300 <= response.status_code < 400:
                result.update(kind='http_error', error=f'Weiterleitung (HTTP {response.status_code}) wird nicht verfolgt')
            else:
                result.update(kind='http_error', error=f'Ziel antwortete mit HTTP {response.status_code}')
                retryable = response.status_code >= 500
        except requests.exceptions.Timeout:
            result.update(kind='timeout', error=f'Timeout nach {webhook["timeout"]} Sekunden', status_code=None)
            retryable = True
        except requests.exceptions.SSLError:
            result.update(kind='tls', error='TLS-Fehler (Zertifikat ungültig oder selbstsigniert?)', status_code=None)
        except requests.exceptions.RequestException as e:
            logger.warning(f'Webhook {webhook["id"]}: Verbindungsfehler: {e}')
            reason = 'Ziel liegt in einem nicht öffentlichen Netzwerk' if 'nicht öffentlichen' in str(e) \
                else 'Verbindung zum Ziel fehlgeschlagen'
            result.update(kind='target_rejected' if 'nicht öffentlichen' in str(e) else 'connection',
                          error=reason, status_code=None)
            retryable = result['kind'] == 'connection'
        if not retryable or attempt == attempts:
            break
        time.sleep(2 ** (attempt - 1))

    result['duration_ms'] = int((time.monotonic() - started) * 1000)
    return result


def log_trigger(webhook, result):
    try:
        with db() as conn:
            conn.execute('''
                INSERT INTO trigger_log (webhook_id, webhook_name, triggered_at, success, status_code,
                                         duration_ms, attempts, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (webhook['id'], webhook['name'], datetime.now(timezone.utc).isoformat(),
                  int(result['success']), result['status_code'], result['duration_ms'],
                  result['attempts'], result['error']))
            conn.execute('DELETE FROM trigger_log WHERE id <= (SELECT MAX(id) FROM trigger_log) - ?', (LOG_KEEP,))
    except Exception as e:
        logger.error(f'Verlauf konnte nicht gespeichert werden: {e}')


TRIGGER_HTTP_STATUS = {'ok': 200, 'target_rejected': 400, 'timeout': 504,
                       'connection': 502, 'tls': 502, 'http_error': 502}


@app.route('/api/webhooks/<int:webhook_id>/trigger', methods=['POST'])
@require_auth
def trigger_webhook(webhook_id):
    """Webhook auslösen"""
    try:
        with db() as conn:
            row = conn.execute('SELECT * FROM webhooks WHERE id = ?', (webhook_id,)).fetchone()
        if not row:
            return jsonify({'error': 'Webhook nicht gefunden'}), 404

        webhook = row_to_webhook(row, mask=False)
        result = execute_webhook(webhook)
        log_trigger(webhook, result)

        if result['success']:
            logger.info(f'Webhook {webhook_id} ausgelöst (Status {result["status_code"]}, '
                        f'{result["duration_ms"]} ms, {result["attempts"]} Versuch(e))')
        else:
            logger.warning(f'Webhook {webhook_id} fehlgeschlagen: {result["error"]}')
        # Antwortinhalt des Ziels wird bewusst nicht zurückgegeben (verhindert das Auslesen interner Dienste)
        body = {k: result[k] for k in ('success', 'status_code', 'duration_ms', 'attempts')}
        if not result['success']:
            body['error'] = result['error']
        return jsonify(body), TRIGGER_HTTP_STATUS[result['kind']]
    except Exception as e:
        logger.error(f'Unerwarteter Fehler beim Auslösen des Webhooks: {e}', exc_info=True)
        return jsonify({'error': 'Interner Fehler'}), 500


# --- Verlauf -----------------------------------------------------------------

def history_rows(webhook_id=None):
    limit, error = parse_int(request.args.get('limit'), 50, 1, 500, 'limit')
    if error:
        return None, error
    query = 'SELECT * FROM trigger_log'
    params = []
    if webhook_id is not None:
        query += ' WHERE webhook_id = ?'
        params.append(webhook_id)
    query += ' ORDER BY id DESC LIMIT ?'
    params.append(limit)
    with db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [{
        'id': r['id'], 'webhook_id': r['webhook_id'], 'webhook_name': r['webhook_name'],
        'triggered_at': r['triggered_at'], 'success': bool(r['success']),
        'status_code': r['status_code'], 'duration_ms': r['duration_ms'],
        'attempts': r['attempts'], 'error': r['error'],
    } for r in rows], None


@app.route('/api/history', methods=['GET'])
@require_auth
def get_history():
    rows, error = history_rows()
    if error:
        return jsonify({'error': error}), 400
    return jsonify(rows)


@app.route('/api/history', methods=['DELETE'])
@require_auth
def clear_history():
    with db() as conn:
        conn.execute('DELETE FROM trigger_log')
    logger.info('Verlauf gelöscht')
    return jsonify({'success': True})


@app.route('/api/webhooks/<int:webhook_id>/history', methods=['GET'])
@require_auth
def get_webhook_history(webhook_id):
    rows, error = history_rows(webhook_id)
    if error:
        return jsonify({'error': error}), 400
    return jsonify(rows)


# --- Export / Import ---------------------------------------------------------

EXPORT_FIELDS = ('name', 'url', 'method', 'description', 'headers', 'body',
                 'timeout', 'retries', 'verify_tls', 'tags')


@app.route('/api/export', methods=['GET'])
@require_auth
def export_webhooks():
    """Alle Webhooks als JSON (inklusive Header-Werte im Klartext, z.B. für Backups)"""
    with db() as conn:
        rows = conn.execute('SELECT * FROM webhooks ORDER BY name COLLATE NOCASE').fetchall()
    webhooks = []
    for row in rows:
        webhook = row_to_webhook(row, mask=False)
        webhooks.append({field: webhook[field] for field in EXPORT_FIELDS})
    payload = json.dumps({'version': 1, 'webhooks': webhooks}, indent=2, ensure_ascii=False)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    logger.info(f'Export von {len(webhooks)} Webhooks')
    return Response(payload, mimetype='application/json',
                    headers={'Content-Disposition': f'attachment; filename="webhooks-{stamp}.json"'})


@app.route('/api/import', methods=['POST'])
@require_auth
def import_webhooks():
    """Webhooks aus einem Export importieren (bereits vorhandene werden übersprungen)"""
    data = request.get_json(silent=True)
    items = data.get('webhooks') if isinstance(data, dict) else None
    if not isinstance(items, list):
        return jsonify({'error': 'Ungültiges Importformat'}), 400
    if len(items) > MAX_IMPORT:
        return jsonify({'error': f'Maximal {MAX_IMPORT} Webhooks pro Import'}), 400

    imported, skipped, errors = 0, 0, []
    with db() as conn:
        existing = {(r['name'], r['url'], r['method']) for r in
                    conn.execute('SELECT name, url, method FROM webhooks').fetchall()}
        for index, item in enumerate(items):
            values, error = parse_webhook_payload(item)
            if error:
                errors.append({'index': index, 'error': error})
                continue
            key = (values['name'], values['url'], values['method'])
            if key in existing:
                skipped += 1
                continue
            conn.execute(INSERT_SQL, webhook_db_values(values))
            existing.add(key)
            imported += 1
    logger.info(f'Import: {imported} importiert, {skipped} übersprungen, {len(errors)} fehlerhaft')
    return jsonify({'imported': imported, 'skipped': skipped, 'errors': errors})


# --- Allgemein ---------------------------------------------------------------

@app.after_request
def set_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('Content-Security-Policy', CONTENT_SECURITY_POLICY)
    if request.path.startswith('/api/'):
        response.headers.setdefault('Cache-Control', 'no-store')
    return response


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint nicht gefunden'}), 404


@app.errorhandler(413)
def too_large(error):
    return jsonify({'error': 'Anfrage ist zu groß'}), 413


@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Interner Server-Fehler: {str(error)}')
    return jsonify({'error': 'Interner Server-Fehler'}), 500


def hash_password_cli():
    import getpass
    password = getpass.getpass('Neues Passwort: ')
    if password != getpass.getpass('Wiederholen: '):
        sys.exit('Passwörter stimmen nicht überein')
    if password in INSECURE_VALUES or len(password) < 8:
        sys.exit('Passwort ist zu schwach (mindestens 8 Zeichen)')
    print(generate_password_hash(password))


if __name__ == '__main__' and '--hash-password' in sys.argv:
    hash_password_cli()
    sys.exit(0)

# Konfiguration prüfen und Datenbank anlegen (auch beim Start über gunicorn)
try:
    check_config()
    init_db()
except Exception as e:
    logger.error(f'Fataler Fehler beim Initialisieren: {e}')
    raise  # gunicorn beendet sich dann ("Worker failed to boot"), statt endlos neu zu starten

if __name__ == '__main__':
    # Nur für die lokale Entwicklung; im Container läuft gunicorn (siehe Dockerfile)
    logger.info(f'Webhook Manager (Entwicklungsserver) startet auf Port {PORT}')
    app.run(host='127.0.0.1', port=PORT, debug=False)
