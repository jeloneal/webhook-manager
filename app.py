#!/usr/bin/env python3
"""
Webhook Manager - Sichere Webanwendung zum Verwalten und Auslösen von Webhooks
"""

import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
import requests
from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
import logging

# Logging konfigurieren
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# CORS für Frontend
CORS(app, supports_credentials=True)

# Konfiguration
PASSWORD = os.environ.get('WEBHOOK_PASSWORD', 'admin123')
DATABASE = os.environ.get('DATABASE_PATH', 'webhooks.db')
PORT = int(os.environ.get('PORT', 5000))

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
        conn = sqlite3.connect(DATABASE)
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
        conn.commit()
        conn.close()
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
    data = request.get_json()
    if not data or 'password' not in data:
        return jsonify({'error': 'Passwort erforderlich'}), 400
    
    if data['password'] == PASSWORD:
        session['authenticated'] = True
        session.permanent = True
        app.permanent_session_lifetime = timedelta(hours=24)
        logger.info('Erfolgreicher Login')
        return jsonify({'success': True})
    else:
        logger.warning('Fehlgeschlagener Login-Versuch')
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
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, url, method, description, created_at FROM webhooks ORDER BY name')
        webhooks = []
        for row in cursor.fetchall():
            webhooks.append({
                'id': row[0],
                'name': row[1],
                'url': row[2],
                'method': row[3],
                'description': row[4],
                'created_at': row[5]
            })
        conn.close()
        return jsonify(webhooks)
    except Exception as e:
        logger.error(f'Fehler beim Laden der Webhooks: {e}')
        return jsonify({'error': 'Fehler beim Laden der Webhooks'}), 500

@app.route('/api/webhooks', methods=['POST'])
@require_auth
def create_webhook():
    """Neuen Webhook erstellen"""
    data = request.get_json()
    
    if not data or not data.get('name') or not data.get('url'):
        return jsonify({'error': 'Name und URL sind erforderlich'}), 400
    
    # URL validieren
    url = data['url'].strip()
    if not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'URL muss mit http:// oder https:// beginnen'}), 400
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO webhooks (name, url, method, description)
            VALUES (?, ?, ?, ?)
        ''', (
            data['name'].strip(),
            url,
            data.get('method', 'POST').upper(),
            data.get('description', '').strip()
        ))
        webhook_id = cursor.lastrowid
        conn.commit()
        conn.close()
        logger.info(f'Webhook erstellt: {data["name"]} (ID: {webhook_id})')
        return jsonify({'id': webhook_id, 'success': True})
    except Exception as e:
        logger.error(f'Fehler beim Erstellen des Webhooks: {e}')
        return jsonify({'error': 'Webhook konnte nicht erstellt werden'}), 500

@app.route('/api/webhooks/<int:webhook_id>', methods=['PUT'])
@require_auth
def update_webhook(webhook_id):
    """Webhook aktualisieren"""
    data = request.get_json()
    
    if not data or not data.get('name') or not data.get('url'):
        return jsonify({'error': 'Name und URL sind erforderlich'}), 400
    
    # URL validieren
    url = data['url'].strip()
    if not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'URL muss mit http:// oder https:// beginnen'}), 400
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE webhooks 
            SET name = ?, url = ?, method = ?, description = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (
            data['name'].strip(),
            url,
            data.get('method', 'POST').upper(),
            data.get('description', '').strip(),
            webhook_id
        ))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Webhook nicht gefunden'}), 404
        
        conn.commit()
        conn.close()
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
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM webhooks WHERE id = ?', (webhook_id,))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Webhook nicht gefunden'}), 404
        
        conn.commit()
        conn.close()
        logger.info(f'Webhook gelöscht: ID {webhook_id}')
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Fehler beim Löschen des Webhooks: {e}')
        return jsonify({'error': 'Webhook konnte nicht gelöscht werden'}), 500

@app.route('/api/webhooks/<int:webhook_id>/trigger', methods=['POST'])
@require_auth
def trigger_webhook(webhook_id):
    """Webhook auslösen"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT name, url, method FROM webhooks WHERE id = ?', (webhook_id,))
        webhook = cursor.fetchone()
        conn.close()
        
        if not webhook:
            return jsonify({'error': 'Webhook nicht gefunden'}), 404
        
        name, url, method = webhook
        
        # Webhook-Request senden
        timeout = 30
        headers = {'User-Agent': 'Webhook-Manager/1.0'}
        
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, timeout=timeout)
        else:
            # Standard: POST mit JSON payload
            payload = {
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'webhook-manager',
                'webhook_id': webhook_id,
                'webhook_name': name
            }
            headers['Content-Type'] = 'application/json'
            response = requests.post(url, json=payload, headers=headers, timeout=timeout)
        
        response.raise_for_status()
        
        logger.info(f'Webhook erfolgreich ausgelöst: {name} (Status: {response.status_code})')
        return jsonify({
            'success': True,
            'status_code': response.status_code,
            'response_text': response.text[:500]  # Erste 500 Zeichen der Antwort
        })
        
    except requests.exceptions.Timeout:
        logger.error(f'Webhook-Timeout: {name}')
        return jsonify({'error': 'Timeout beim Auslösen des Webhooks'}), 408
    
    except requests.exceptions.RequestException as e:
        logger.error(f'Webhook-Fehler für {name}: {str(e)}')
        return jsonify({'error': f'Fehler beim Auslösen: {str(e)}'}), 400
    
    except Exception as e:
        logger.error(f'Unerwarteter Fehler beim Auslösen des Webhooks: {e}')
        return jsonify({'error': 'Interner Fehler'}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint nicht gefunden'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Interner Server-Fehler: {str(error)}')
    return jsonify({'error': 'Interner Server-Fehler'}), 500

if __name__ == '__main__':
    # Datenbank initialisieren
    logger.info(f'Initialisiere Webhook Manager...')
    logger.info(f'Datenbank-Pfad: {DATABASE}')
    logger.info(f'Port: {PORT}')
    
    try:
        init_db()
    except Exception as e:
        logger.error(f'Fataler Fehler beim Initialisieren: {e}')
        exit(1)
    
    # Server starten
    logger.info(f'Webhook Manager startet auf Port {PORT}')
    app.run(host='0.0.0.0', port=PORT, debug=False)
