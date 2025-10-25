# Webhook Manager

Sichere Web-Anwendung zum Verwalten und Auslösen von Webhooks. Ideal für Home-Automation, CI/CD-Pipelines und API-Testing.

## Features

- ✅ **Sicher**: Passwortgeschützter Zugang
- ✅ **Einfach**: Minimalistische Benutzeroberfläche
- ✅ **Flexibel**: Unterstützt GET und POST Requests
- ✅ **Persistent**: SQLite-Datenbank für alle Webhooks
- ✅ **Docker-ready**: Schnelle Deployment mit Docker
- ✅ **Traefik-kompatibel**: Einfache Integration mit Reverse Proxy
- ✅ **Lightweight**: Minimale Abhängigkeiten

## Schnellstart

### Voraussetzungen

- Docker & Docker Compose
- (Optional) Traefik als Reverse Proxy

### Installation

1. **Repository klonen:**
```bash
git clone https://github.com/your-username/webhook-manager.git
cd webhook-manager
```

2. **Umgebungsvariablen anpassen:**

Bearbeite `docker-compose.yml` und ändere:
- `WEBHOOK_PASSWORD`: Dein sicheres Passwort
- `SECRET_KEY`: Zufälliger String für Session-Sicherheit
- Traefik-Domain: `webhooks.example.com` durch deine Domain ersetzen

3. **Container starten:**

**Mit Traefik:**
```bash
docker-compose up -d
```

**Ohne Traefik (Standalone):**
```bash
docker-compose -f docker-compose-standalone.yml up -d
```

4. **Anwendung öffnen:**
- Mit Traefik: `https://webhooks.example.com`
- Standalone: `http://localhost:5000`

## Konfiguration

### Umgebungsvariablen

| Variable | Beschreibung | Standard |
|----------|--------------|----------|
| `WEBHOOK_PASSWORD` | Passwort für Login | `admin123` |
| `SECRET_KEY` | Session-Secret | auto-generiert |
| `DATABASE_PATH` | Pfad zur SQLite-DB | `/app/data/webhooks.db` |
| `PORT` | Server-Port | `5000` |

### Traefik-Integration

Die `docker-compose.yml` enthält vorkonfigurierte Traefik-Labels:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.webhook-manager.rule=Host(`webhooks.example.com`)"
  - "traefik.http.routers.webhook-manager.entrypoints=websecure"
  - "traefik.http.routers.webhook-manager.tls.certresolver=letsencrypt"
```

**Wichtig:** Stelle sicher, dass das `traefik-net` Netzwerk existiert:
```bash
docker network create traefik-net
```

### Optionale Basic Auth

Für zusätzliche Sicherheit kann Basic Auth aktiviert werden:

1. Passwort-Hash erzeugen:
```bash
htpasswd -nb admin dein-passwort
```

2. In `docker-compose.yml` auskommentieren und Hash eintragen:
```yaml
- "traefik.http.routers.webhook-manager.middlewares=webhook-auth"
- "traefik.http.middlewares.webhook-auth.basicauth.users=admin:$$apr1$$..."
```

## Verwendung

### 1. Login
- Öffne die Anwendung
- Gib dein konfiguriertes Passwort ein

### 2. Webhook erstellen
- Klicke auf "Neu anlegen"
- Gib Name, URL und Beschreibung ein
- Wähle Methode (GET oder POST)
- Speichern

### 3. Webhook auslösen
- Klicke auf den Button des gewünschten Webhooks
- Bestätige die Ausführung
- Erhalte Status-Feedback (Erfolg/Fehler)

### 4. Webhook bearbeiten/löschen
- Klicke auf "Bearbeiten" oder "Löschen"
- Nehme Änderungen vor
- Speichern

## API-Endpunkte

Die Anwendung bietet eine RESTful API:

### Authentifizierung

**POST** `/api/login`
```json
{
  "password": "dein-passwort"
}
```

**POST** `/api/logout`

**GET** `/api/status`

### Webhook-Verwaltung

**GET** `/api/webhooks` - Alle Webhooks abrufen

**POST** `/api/webhooks` - Neuen Webhook erstellen
```json
{
  "name": "Beispiel Webhook",
  "url": "https://api.example.com/webhook",
  "method": "POST",
  "description": "Optionale Beschreibung"
}
```

**PUT** `/api/webhooks/{id}` - Webhook aktualisieren

**DELETE** `/api/webhooks/{id}` - Webhook löschen

**POST** `/api/webhooks/{id}/trigger` - Webhook auslösen

## Sicherheit

### Empfohlene Maßnahmen

1. **Starkes Passwort verwenden**
   - Mindestens 16 Zeichen
   - Keine Standard-Passwörter

2. **HTTPS aktivieren**
   - Nutze Traefik mit Let's Encrypt
   - Oder stelle eigenes SSL-Zertifikat bereit

3. **Netzwerk-Isolation**
   - Container nur im benötigten Netzwerk
   - Firewall-Regeln konfigurieren

4. **Regelmäßige Updates**
   ```bash
   docker-compose pull
   docker-compose up -d
   ```

5. **Backup der Datenbank**
   ```bash
   cp data/webhooks.db data/webhooks.db.backup
   ```

6. **Optional: Fail2Ban**
   - Schutz vor Brute-Force-Angriffen
   - Log-Monitoring aktivieren

## Entwicklung

### Lokal ohne Docker

1. **Python-Environment erstellen:**
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

2. **Dependencies installieren:**
```bash
pip install -r requirements.txt
```

3. **Umgebungsvariablen setzen:**
```bash
export WEBHOOK_PASSWORD=test123
export DATABASE_PATH=webhooks.db
```

4. **Anwendung starten:**
```bash
python app.py
```

5. **Öffne:** `http://localhost:5000`

### Build & Push

```bash
# Build
docker build -t webhook-manager:latest .

# Tag für Registry
docker tag webhook-manager:latest your-registry/webhook-manager:latest

# Push
docker push your-registry/webhook-manager:latest
```

## Troubleshooting

### Container startet nicht

```bash
# Logs prüfen
docker-compose logs -f webhook-manager

# Container neu starten
docker-compose restart webhook-manager
```

### Datenbank-Fehler

```bash
# Datenbank zurücksetzen (ACHTUNG: Löscht alle Daten!)
rm data/webhooks.db
docker-compose restart webhook-manager
```

### Traefik findet Container nicht

```bash
# Netzwerk prüfen
docker network ls
docker network inspect traefik-net

# Labels prüfen
docker inspect webhook-manager | grep -A 20 Labels
```

### Webhook wird nicht ausgelöst

- URL auf Erreichbarkeit prüfen
- Firewall-Regeln kontrollieren
- Logs für detaillierte Fehlermeldung ansehen

## Datensicherung

### Automatisches Backup-Script

```bash
#!/bin/bash
# backup.sh
BACKUP_DIR="./backups"
mkdir -p $BACKUP_DIR
DATE=$(date +%Y%m%d_%H%M%S)
cp data/webhooks.db "$BACKUP_DIR/webhooks_$DATE.db"
# Alte Backups löschen (älter als 30 Tage)
find $BACKUP_DIR -name "webhooks_*.db" -mtime +30 -delete
```

Cron-Job einrichten:
```bash
0 2 * * * /path/to/backup.sh
```

## Lizenz

MIT License - siehe LICENSE-Datei

## Support

Bei Fragen oder Problemen erstelle ein Issue auf GitHub.

## Roadmap

- [ ] Webhook-Historie mit Logs
- [ ] Custom Headers für Requests
- [ ] Webhook-Gruppen
- [ ] Rate Limiting
- [ ] Multi-User Support
- [ ] Webhook-Templates
- [ ] API-Key Authentifizierung
- [ ] Export/Import von Webhooks

## Beitragende

Contributions sind willkommen! Bitte erstelle einen Pull Request.

1. Fork das Repository
2. Erstelle einen Feature-Branch (`git checkout -b feature/AmazingFeature`)
3. Committe deine Änderungen (`git commit -m 'Add some AmazingFeature'`)
4. Push zum Branch (`git push origin feature/AmazingFeature`)
5. Öffne einen Pull Request