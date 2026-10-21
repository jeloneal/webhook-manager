#!/usr/bin/env python3
"""
Webhook Manager - Sichere Webanwendung zum Verwalten und Auslösen von Webhooks
"""

import os
import hmac
import time
import socket
import sqlite3
import ipaddress
import threading
from contextlib import contextmanager
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from functools import wraps
import requests
from flask import Flask, request, jsonify, session, send_from_directory
import logging

# Logging konfigurieren
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Konfiguration
PASSWORD = os.environ.get('WEBHOOK_PASSWORD', '')
SECRET_KEY = os.environ.get('SECRET_KEY', '')
DATABASE = os.environ.get('DATABASE_PATH', 'webhooks.db')
PORT = int(os.environ.get('PORT', 5000))
# Session-Cookie nur über HTTPS senden; für reinen HTTP-Betrieb (z.B. localhost) auf "false" setzen
COOKIE_SECURE = os.environ.get('COOKIE_SECURE', 'true').lower() != 'false'
# Standardmäßig sind Ziele in privaten/internen Netzen gesperrt (SSRF-Schutz)
ALLOW_PRIVATE_TARGETS = os.environ.get('ALLOW_PRIVATE_TARGETS', 'false').lower() == 'true'

ALLOWED_METHODS = ('GET', 'POST')
MAX_NAME_LEN = 200
MAX_URL_LEN = 2048
MAX_DESCRIPTION_LEN = 2000

# Bekannte Beispielwerte, mit denen die App nicht starten darf
INSECURE_VALUES = {'', 'admin123', 'your-secret-key-change-me', 'changeme', 'password'}

# Brute-Force-Schutz für den Login
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
_failed_logins = {}
_failed_logins_lock = threading.Lock()


def check_config():
    """Bricht ab, wenn unsichere Standardwerte konfiguriert sind"""
    if PASSWORD in INSECURE_VALUES:
        raise RuntimeError('WEBHOOK_PASSWORD muss gesetzt und darf kein Beispielwert sein')
    if SECRET_KEY in INSECURE_VALUES or len(SECRET_KEY) < 16:
        raise RuntimeError('SECRET_KEY muss gesetzt sein (mindestens 16 Zeichen, kein Beispielwert)')


app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
)

# Hinweis: Das Frontend wird vom selben Server ausgeliefert, daher ist kein CORS nötig.


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


def validate_target_url(url):
    """Prüft eine Webhook-URL. Gibt eine Fehlermeldung zurück oder None, wenn gültig.

    Löst den Hostnamen auf und lehnt (außer bei ALLOW_PRIVATE_TARGETS) alle
    Adressen ab, die nicht öffentlich routbar sind (Loopback, private Netze,
    Link-Local/Cloud-Metadaten usw.).
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
        infos = socket.getaddrinfo(hostname, port or (443 if parsed.scheme == 'https' else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return 'Host konnte nicht aufgelöst werden'
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split('%')[0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            return 'Ziel liegt in einem nicht öffentlichen Netzwerk'
    return None


def parse_webhook_payload(data):
    """Validiert Eingabedaten. Gibt (werte, fehler) zurück."""
    if not isinstance(data, dict):
        return None, 'Ungültige Anfrage'
    name, url = data.get('name'), data.get('url')
    method = data.get('method', 'POST')
    description = data.get('description') or ''
    if not all(isinstance(v, str) for v in (name, url, method, description)):
        return None, 'Ungültige Feldtypen'
    name, url, description = name.strip(), url.strip(), description.strip()
    method = method.strip().upper()
    if not name or not url:
        return None, 'Name und URL sind erforderlich'
    if len(name) > MAX_NAME_LEN or len(description) > MAX_DESCRIPTION_LEN:
        return None, 'Name oder Beschreibung ist zu lang'
    if method not in ALLOWED_METHODS:
        return None, 'Methode muss GET oder POST sein'
    error = validate_target_url(url)
    if error:
        return None, error
    return (name, url, method, description), None


@contextmanager
def db():
    """SQLite-Verbindung, die immer geschlossen wird (Commit bei Erfolg, Rollback bei Fehler)"""
    conn = sqlite3.connect(DATABASE)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db():
    """Initialisiert die SQLite-Datenbank"""
    # Verzeichnis erstellen, falls nicht vorhanden
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
        logger.info(f'Datenbank erfolgreich initialisiert: {DATABASE}')
    except Exception as e:
        logger.error(f'Fehler beim Initialisieren der Datenbank: {e}')
        raise

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

    if hmac.compare_digest(data['password'].encode('utf-8'), PASSWORD.encode('utf-8')):
        session.clear()
        session['authenticated'] = True
        session.permanent = True
        logger.info('Erfolgreicher Login')
        return jsonify({'success': True})
    else:
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

@app.route('/api/webhooks', methods=['GET'])
@require_auth
def get_webhooks():
    """Alle Webhooks abrufen"""
    try:
        with db() as conn:
            rows = conn.execute(
                'SELECT id, name, url, method, description, created_at FROM webhooks ORDER BY name'
            ).fetchall()
        webhooks = [{
            'id': row[0],
            'name': row[1],
            'url': row[2],
            'method': row[3],
            'description': row[4],
            'created_at': row[5]
        } for row in rows]
        return jsonify(webhooks)
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
            cursor = conn.execute('''
                INSERT INTO webhooks (name, url, method, description)
                VALUES (?, ?, ?, ?)
            ''', values)
            webhook_id = cursor.lastrowid
        logger.info(f'Webhook erstellt: {values[0]} (ID: {webhook_id})')
        return jsonify({'id': webhook_id, 'success': True})
    except Exception as e:
        logger.error(f'Fehler beim Erstellen des Webhooks: {e}')
        return jsonify({'error': 'Webhook konnte nicht erstellt werden'}), 500

@app.route('/api/webhooks/<int:webhook_id>', methods=['PUT'])
@require_auth
def update_webhook(webhook_id):
    """Webhook aktualisieren"""
    values, error = parse_webhook_payload(request.get_json(silent=True))
    if error:
        return jsonify({'error': error}), 400
    
    try:
        with db() as conn:
            cursor = conn.execute('''
                UPDATE webhooks 
                SET name = ?, url = ?, method = ?, description = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', values + (webhook_id,))
            found = cursor.rowcount > 0
        
        if not found:
            return jsonify({'error': 'Webhook nicht gefunden'}), 404
        
        logger.info(f'Webhook aktualisiert: ID {webhook_id}')
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Fehler beim Aktualisieren des Webhooks: {e}')
        return jsonify({'error': 'Webhook konnte nicht aktualisiert werden'}), 500

@app.route('/api/webhooks/<int:webhook_id>', methods=['DELETE'])
@require_auth
def delete_webhook(webhook_id):
    """Webhook löschen"""
    try:
        with db() as conn:
            found = conn.execute('DELETE FROM webhooks WHERE id = ?', (webhook_id,)).rowcount > 0
        
        if not found:
            return jsonify({'error': 'Webhook nicht gefunden'}), 404
        
        logger.info(f'Webhook gelöscht: ID {webhook_id}')
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Fehler beim Löschen des Webhooks: {e}')
        return jsonify({'error': 'Webhook konnte nicht gelöscht werden'}), 500

@app.route('/api/webhooks/<int:webhook_id>/trigger', methods=['POST'])
@require_auth
def trigger_webhook(webhook_id):
    """Webhook auslösen"""
    name = f'ID {webhook_id}'
    try:
        with db() as conn:
            webhook = conn.execute(
                'SELECT name, url, method FROM webhooks WHERE id = ?', (webhook_id,)
            ).fetchone()
        
        if not webhook:
            return jsonify({'error': 'Webhook nicht gefunden'}), 404
        
        name, url, method = webhook

        # Ziel bei jedem Auslösen erneut prüfen (DNS kann sich seit dem Speichern geändert haben)
        error = validate_target_url(url)
        if error:
            logger.warning(f'Webhook-Ziel abgelehnt: {name}: {error}')
            return jsonify({'error': error}), 400
        
        # Webhook-Request senden
        timeout = 30
        headers = {'User-Agent': 'Webhook-Manager/1.0'}
        
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        else:
            # Standard: POST mit JSON payload
            payload = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'webhook-manager',
                'webhook_id': webhook_id,
                'webhook_name': name
            }
            headers['Content-Type'] = 'application/json'
            response = requests.post(url, json=payload, headers=headers, timeout=timeout, allow_redirects=False)
        
        response.raise_for_status()
        
        logger.info(f'Webhook erfolgreich ausgelöst: {name} (Status: {response.status_code})')
        # Antwortinhalt wird bewusst nicht zurückgegeben (verhindert das Auslesen interner Dienste)
        return jsonify({
            'success': True,
            'status_code': response.status_code
        })
        
    except requests.exceptions.Timeout:
        logger.error(f'Webhook-Timeout: {name}')
        return jsonify({'error': 'Timeout beim Auslösen des Webhooks'}), 408
    
    except requests.exceptions.RequestException as e:
        logger.error(f'Webhook-Fehler für {name}: {str(e)}')
        return jsonify({'error': 'Fehler beim Auslösen des Webhooks'}), 400
    
    except Exception as e:
        logger.error(f'Unerwarteter Fehler beim Auslösen des Webhooks: {e}')
        return jsonify({'error': 'Interner Fehler'}), 500

@app.after_request
def set_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    if request.path.startswith('/api/'):
        response.headers.setdefault('Cache-Control', 'no-store')
    return response

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint nicht gefunden'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Interner Server-Fehler: {str(error)}')
    return jsonify({'error': 'Interner Server-Fehler'}), 500

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
