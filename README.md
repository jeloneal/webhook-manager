# Webhook Manager

Sichere Web-Anwendung zum Verwalten und Auslösen von Webhooks. Ideal für Home-Automation, CI/CD-Pipelines und API-Testing.

## Features

- ✅ **Sicher**: Passwortschutz (optional als Hash), SSRF-Schutz, Rate-Limit, CSP, maskierte Header-Werte
- ✅ **Flexibel**: GET, POST, PUT, PATCH, DELETE mit eigenen Headern, Body-Vorlage, Timeout und Wiederholungen
- ✅ **Nachvollziehbar**: Verlauf aller Auslösungen (Zeit, HTTP-Status, Dauer, Fehler)
- ✅ **Übersichtlich**: Suche, Tags und Sortierung
- ✅ **Portabel**: Export/Import als JSON
- ✅ **Persistent**: SQLite-Datenbank mit automatischen Schema-Migrationen
- ✅ **Docker-ready**: gunicorn, non-root, Healthcheck (`/healthz`), optional JSON-Logs
- ✅ **Traefik-kompatibel**: Einfache Integration mit Reverse Proxy

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

Lege neben der Compose-Datei eine `.env` an (Werte mit `$` in einfache Anführungszeichen setzen):
```bash
SECRET_KEY=$(openssl rand -hex 32)      # Zufälliger String für Session-Sicherheit
WEBHOOK_PASSWORD='dein-langes-passwort'  # ODER besser: WEBHOOK_PASSWORD_HASH (siehe unten)
ALLOWED_PRIVATE_HOSTS=portainer.lan      # nur nötig für Ziele im privaten Netz
```
Außerdem in `docker-compose.yml` die Traefik-Domain `webhooks.example.com` durch deine Domain ersetzen.
Ohne `SECRET_KEY` und Passwort (bzw. Hash) startet die App absichtlich nicht.

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
| `WEBHOOK_PASSWORD` | Passwort für Login (Klartext). Eines von `WEBHOOK_PASSWORD` / `WEBHOOK_PASSWORD_HASH` ist **Pflicht** | – |
| `WEBHOOK_PASSWORD_HASH` | Passwort-Hash statt Klartext, erzeugen mit `python app.py --hash-password` (hat Vorrang) | – |
| `SECRET_KEY` | Session-Secret, mind. 16 Zeichen (**Pflicht**) | – |
| `COOKIE_SECURE` | Session-Cookie nur über HTTPS senden; für reinen HTTP-Betrieb `false` | `true` |
| `ALLOWED_PRIVATE_HOSTS` | Kommagetrennte Hostnamen/IPs, die auch auf private Adressen zeigen dürfen (z. B. `portainer.lan,10.0.0.5`) | leer |
| `ALLOW_PRIVATE_TARGETS` | Alle privaten Ziele erlauben (SSRF-Schutz komplett aus; besser `ALLOWED_PRIVATE_HOSTS` nutzen) | `false` |
| `TRUSTED_PROXIES` | Anzahl vorgeschalteter Reverse-Proxys (Traefik: `1`), damit das Login-Limit pro Client-IP zählt. Nur setzen, wenn die App ausschließlich über den Proxy erreichbar ist | `0` |
| `LOG_FORMAT` | `text` oder `json` (strukturierte Logs) | `text` |
| `DATABASE_PATH` | Pfad zur SQLite-DB | `/app/data/webhooks.db` |
| `PORT` | Server-Port | `5000` |

**Passwort-Hash erzeugen** (landet nicht im Klartext in der Umgebung):
```bash
docker compose run --rm webhook-manager python app.py --hash-password
# Ausgabe in die .env übernehmen, in einfachen Anführungszeichen:
# WEBHOOK_PASSWORD_HASH='scrypt:32768:8:1$...'
```

### Portainer (Stack-Updates auslösen)

1. In Portainer beim Stack (oder Service) **Webhook** aktivieren und die URL kopieren, z. B.
   `https://portainer.example.com/api/stacks/webhooks/<uuid>` (Services: `/api/webhooks/<uuid>`).
2. Im Webhook Manager einen Webhook mit **Methode POST** und dieser URL anlegen. Portainer antwortet mit HTTP 204; ein Body ist nicht nötig.
3. Liegt Portainer im privaten Netz oder im selben Docker-Netzwerk, den Hostnamen in `ALLOWED_PRIVATE_HOSTS` eintragen (z. B. `portainer`). Andere private Ziele bleiben gesperrt.
4. Hat Portainer ein selbstsigniertes Zertifikat: unter **Erweitert** „TLS-Zertifikat prüfen“ abschalten (oder besser das Zertifikat trusten / ein gültiges verwenden).
5. Optional: **Wiederholungen** auf 1–2 setzen, falls Portainer kurz nicht erreichbar ist (z. B. während eines Updates).

Die Portainer-Webhook-URL enthält das Geheimnis (UUID) und wird in der Datenbank im Klartext gespeichert; sie taucht auch im Export auf.

> **Datenhaltung:** Die Datenbank liegt im Docker-Named-Volume `webhook-data` (nicht mehr in `./data`). Der Container läuft als User `appuser` (UID 1000); das Named Volume erhält die passenden Rechte automatisch.
>
> **Migration von einer älteren Version mit `./data`:**
> ```bash
> docker compose up -d --no-start            # legt das Volume an
> docker run --rm -v "$(pwd)/data:/from:ro" -v webhook-manager_webhook-data:/to alpine \
>   sh -c 'cp /from/webhooks.db /to/ && chown 1000:1000 /to/webhooks.db'
> docker compose up -d
> ```
> (Der Volume-Name enthält den Projektnamen, prüfen mit `docker volume ls`.) Wer lieber beim Bind-Mount bleibt, muss das Host-Verzeichnis für UID 1000 beschreibbar machen: `sudo chown 1000:1000 data`.

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
- Gib Name, URL und Beschreibung ein, optional Tags
- Wähle die Methode (GET, POST, PUT, PATCH, DELETE)
- Unter „Erweitert“: eigene Header (`Name: Wert`), Body-Vorlage mit `{{timestamp}}`, `{{webhook_id}}`, `{{webhook_name}}`, Timeout (1–60 s), Wiederholungen (0–3) und TLS-Prüfung
- Header-Werte werden nach dem Speichern maskiert (`********`); bleibt der Platzhalter beim Bearbeiten stehen, behält der Header seinen Wert
- Speichern

### 3. Webhook auslösen
- Klicke auf den Button des gewünschten Webhooks
- Bestätige die Ausführung
- Erhalte Status-Feedback (HTTP-Status, Dauer, Anzahl Versuche; bei Fehlern die Ursache)
- Der Antwortinhalt des Ziels wird bewusst nicht angezeigt (verhindert das Auslesen interner Dienste)

### 3a. Verlauf, Suche, Export
- **📜 Verlauf** (pro Webhook oder gesamt): Zeitpunkt, Ergebnis, Dauer, Versuche, Fehler. Es werden die letzten 2000 Einträge behalten.
- Suche über Name, URL, Beschreibung und Tags; Filter per Tag; Sortierung nach Name, zuletzt ausgelöst oder neuester
- **Export/Import** als JSON. Der Export enthält Header-Werte im Klartext, die Datei also sicher aufbewahren. Beim Import werden Duplikate (Name, URL, Methode) übersprungen

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
  "name": "Stack aktualisieren",
  "url": "https://portainer.example.com/api/stacks/webhooks/<uuid>",
  "method": "POST",
  "description": "Optionale Beschreibung",
  "tags": ["prod", "portainer"],
  "headers": {"X-API-Key": "..."},
  "body": "{\"stack\": \"{{webhook_name}}\"}",
  "timeout": 30,
  "retries": 1,
  "verify_tls": true
}
```
Nur `name` und `url` sind Pflicht. Ohne `body` wird bei POST/PUT/PATCH ein JSON mit Zeitstempel und Webhook-Namen gesendet.

**PUT** `/api/webhooks/{id}` - Webhook aktualisieren (Header-Wert `********` behält den gespeicherten Wert)

**DELETE** `/api/webhooks/{id}` - Webhook löschen (inklusive Verlauf)

**POST** `/api/webhooks/{id}/trigger` - Webhook auslösen. Antwort: `success`, `status_code`, `duration_ms`, `attempts` (bei Fehlern `error`). HTTP-Status: `200` OK, `400` Ziel nicht erlaubt, `502` Ziel/Verbindung fehlgeschlagen, `504` Timeout

### Verlauf, Export, Import

**GET** `/api/history?limit=50` · **GET** `/api/webhooks/{id}/history` · **DELETE** `/api/history`

**GET** `/api/export` - Alle Webhooks als JSON-Datei

**POST** `/api/import` - `{"webhooks": [...]}` im Format des Exports; Antwort: `imported`, `skipped`, `errors`

### Betrieb

**GET** `/healthz` - Liveness/Readiness ohne Login (prüft die Datenbank)

## Sicherheit

### Empfohlene Maßnahmen

1. **Starkes Passwort verwenden** (am besten als `WEBHOOK_PASSWORD_HASH`)
   - Mindestens 16 Zeichen
   - Die App startet nicht mit Beispiel-Passwörtern oder -Secrets

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
   docker compose cp webhook-manager:/app/data/webhooks.db ./webhooks.db.backup
   ```

6. **Eingebaute Schutzmaßnahmen**
   - SSRF-Schutz: Ziele werden beim Verbindungsaufbau aufgelöst und geprüft (kein DNS-Rebinding); Loopback, private Netze und Cloud-Metadaten sind gesperrt, Ausnahmen nur über `ALLOWED_PRIVATE_HOSTS`; Redirects werden nicht verfolgt
   - Login-Rate-Limit (5 Fehlversuche je IP in 15 Minuten); hinter Traefik `TRUSTED_PROXIES=1` setzen
   - Session-Cookie `HttpOnly`, `SameSite=Strict`, `Secure`; kein CORS; Content-Security-Policy
   - Header-Werte (z. B. Tokens) werden von der API nie zurückgegeben. In der Datenbank liegen sie, wie die URLs, im Klartext: Volume und Backups entsprechend schützen
   - Optional zusätzlich: Fail2Ban auf Basis der Logs (`LOG_FORMAT=json`)

## Entwicklung

### Lokal ohne Docker

1. **Python-Environment erstellen:**
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

2. **Dependencies installieren:**
```bash
pip install -r requirements-dev.txt
```

3. **Umgebungsvariablen setzen:**
```bash
export WEBHOOK_PASSWORD=ein-lokales-testpasswort
export SECRET_KEY=$(openssl rand -hex 32)
export DATABASE_PATH=webhooks.db
export COOKIE_SECURE=false   # lokal ohne HTTPS
```

4. **Anwendung starten:**
```bash
python app.py
```

5. **Öffne:** `http://localhost:5000`

### Tests

```bash
python -m pytest -q          # Tests (Validierung, SSRF-Schutz, Auslösen, Verlauf, Import/Export, Migrationen)
pip-audit -r requirements.txt  # bekannte Schwachstellen in den Abhängigkeiten
```
Die GitHub-Action `.github/workflows/ci.yml` führt beides aus und baut zusätzlich das Docker-Image (inklusive Healthcheck).

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
docker compose down
docker volume rm webhook-manager_webhook-data
docker compose up -d
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

- Im **Verlauf** (📜) steht die Ursache: HTTP-Status, Timeout, TLS-Fehler oder „Ziel liegt in einem nicht öffentlichen Netzwerk“
- „Ziel liegt in einem nicht öffentlichen Netzwerk“: den Hostnamen in `ALLOWED_PRIVATE_HOSTS` eintragen
- TLS-Fehler bei selbstsignierten Zertifikaten: unter „Erweitert“ die TLS-Prüfung abschalten
- Logs ansehen: `docker compose logs webhook-manager`

## Datensicherung

### Automatisches Backup-Script

```bash
#!/bin/bash
# backup.sh
BACKUP_DIR="./backups"
mkdir -p $BACKUP_DIR
DATE=$(date +%Y%m%d_%H%M%S)
docker compose cp webhook-manager:/app/data/webhooks.db "$BACKUP_DIR/webhooks_$DATE.db"
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

- [x] Webhook-Historie mit Logs
- [x] Custom Headers, Body-Vorlagen, Timeout und Wiederholungen
- [x] Tags, Suche und Sortierung
- [x] Export/Import von Webhooks
- [ ] Verschlüsselung der Header-Werte in der Datenbank
- [ ] Multi-User Support (bewusst nicht umgesetzt: die App ist für den Einzelbetrieb gedacht)

## Beitragende

Contributions sind willkommen! Bitte erstelle einen Pull Request.

1. Fork das Repository
2. Erstelle einen Feature-Branch (`git checkout -b feature/AmazingFeature`)
3. Committe deine Änderungen (`git commit -m 'Add some AmazingFeature'`)
4. Push zum Branch (`git push origin feature/AmazingFeature`)
5. Öffne einen Pull Request