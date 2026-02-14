# Atemschutz-Log — Kurzanleitung (sehr einfach)
Was ist das?
- Eine kleine Web‑Seite zum Eintragen von Atemschutz‑Daten. Wenn du auf "SPEICHERN" klickst, wird der Eintrag an einen Discord‑Channel geschickt (über einen Webhook).
Schnellstart (Windows, Schritt für Schritt)
1) Dateien herunterladen
- Du solltest den Ordner `d:\Atemschutzüberwachung` haben (die Dateien in diesem Repo).
2) Python‑Umgebung anlegen (einmal):
Öffne PowerShell im Ordner `d:\Atemschutzüberwachung` und tippe:
```powershell
python -m venv .venv
.venv\Scripts\Activate
.venv\Scripts\python -m pip install -r requirements.txt
3) Webhook und geheimes Passwort setzen
- Öffne die Datei `.env` im Projektordner (ist schon angelegt) und trage dort ein:
```
DISCORD_WEBHOOK_URL=DEINE_WEBHOOK_URL_HIER
FLASK_SECRET=ein-geheimes-passwort
PORT=5000
ODER (temporär für diese PowerShell‑Sitzung) setze die Variablen so:
```powershell
$env:DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/...'  
$env:FLASK_SECRET = 'mein-geheimes-passwort'
.venv\Scripts\python app.py
4) App starten
- Wenn `.env` gefüllt ist oder du die Umgebungsvariablen gesetzt hast, starte die App:
```powershell
.venv\Scripts\python app.py
```
- Öffne dann im Browser: http://127.0.0.1:5000/
5) Nur das Aussehen prüfen (ohne Server)
- Wenn du nur das Formular anschauen willst, öffne `templates/index.html` in VS Code und Rechtsklick → "Open with Live Server".
6) Logo hinzufügen
- Lege dein BF‑München‑Logo als `bf_muenchen.png` im Ordner `static` ab:
```
d:\Atemschutzüberwachung\static\bf_muenchen.png
```
7) Test‑Nachricht an Discord (optional)
- Mit curl (Terminal):
```bash
curl -H "Content-Type: application/json" -d '{"content":"Test Nachricht"}' %WEBHOOK_URL%
```
Oder mit Python:
```python
import os, requests
url = os.environ.get('DISCORD_WEBHOOK_URL')
requests.post(url, json={"content":"Test Nachricht"})
```
Probleme? (schnelle Checks)
- Wenn `ModuleNotFoundError: No module named 'flask'` erscheint, führe aus:
```powershell
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -c "import flask; print('flask OK', flask.__version__)"
```
- Prüfe, ob du wirklich die venv‑Python benutzt:
```powershell
.venv\Scripts\python -c "import sys; print(sys.executable)"
```
- Wenn der Webhook nicht ankommt: prüfe die URL in `.env` und öffne die Browser‑Konsole oder schau in die Flash‑Meldungen auf der Seite.
Mehr Hilfe
- Sag mir einfach, welcher Schritt nicht klappt (Kopiere/füge die Fehlermeldung). Ich helfe dir dann Schritt‑für‑Schritt.
# Atemschutz-Log (kleines Demo-Projekt)

Ein kleines Flask-Webformular zum Erfassen von Atemschutz-Überwachungsdaten. Beim Speichern wird ein Discord-Webhook (mit optionalem Foto) angesteuert und der Eintrag im Ziel-Channel gepostet.

Setup

1. Python-Umgebung vorbereiten

```bash
python -m venv .venv
source .venv/Scripts/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```


2. Umgebung konfigurieren

Erstelle eine `.env`-Datei oder setze Umgebungsvariablen:

```
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
FLASK_SECRET=ein-geheimes-token
```

3. Live Server (schnell, statisch testen)

Wenn du mit der VS Code Live Server Extension arbeitest und nicht die Flask-App starten möchtest, öffnet Live Server standardmäßig das Projekt-Root. Damit die Tablet-Seite direkt angezeigt wird, gibt es zwei Möglichkeiten:

- Variante A (einfach): Öffne `templates/index.html` in VS Code, Rechtsklick → "Open with Live Server".

- Variante B (automatisch): Live Server öffnet nun `index.html` im Projekt-Root, das hier bereits eine Weiterleitung auf `templates/index.html` enthält. Jetzt genügt in VS Code ein normaler "Open with Live Server" im Projekt-Root.

4. Flask‑Backend (Webhook, echtes Senden)

Wenn du das Formular wirklich an einen Discord-Channel schicken möchtest, starte die Flask‑App (empfohlen für Produktion / echtes POSTing):

Windows (PowerShell) — empfohlene, venv-sichere Schritte

```powershell
# im Projektordner
python -m venv .venv
.venv\Scripts\Activate
.venv\Scripts\python -m pip install -r requirements.txt

# Option A: Für eine einmalige Sitzung Umgebungsvariablen setzen (nur PowerShell):
$env:DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/...'  # setze deine URL hier
$env:FLASK_SECRET = 'ein-geheimes-token'
.venv\Scripts\python app.py

# Option B (besser): Werte in .env eintragen (bereits im Repo). python-dotenv lädt diese automatisch:
# DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
# FLASK_SECRET=ein-geheimes-token
# dann einfach:
.venv\Scripts\python app.py
```

Die App läuft dann unter `http://127.0.0.1:5000/` und das Formular wird beim Absenden an die in `DISCORD_WEBHOOK_URL` hinterlegte Webhook-URL gesendet.

5. Discord Webhook anlegen & testen

1. Kanal auswählen → Kanal-Einstellungen → Integrationen → Webhooks → "Neuen Webhook erstellen".
2. Namen + Channel wählen → Webhook-URL kopieren.
3. In der lokalen Umgebung die Variable `DISCORD_WEBHOOK_URL` auf die kopierte URL setzen.

Schnelltest via `curl` (nur Text):

```bash
curl -H "Content-Type: application/json" -d '{"content":"Test Nachricht vom Atemschutz-Formular"}' https://discord.com/api/webhooks/....
```

Python-Test mit `requests`:

```python
import os, requests
url = os.environ.get('DISCORD_WEBHOOK_URL')
requests.post(url, json={"content":"Test Nachricht vom Atemschutz-Formular"})
```

Hinweis zu Dateien: Die App sendet nur Textdaten für das Formular; frühere Versionen unterstützten Bilduploads. Die aktuelle Template verwendet dynamische `trupps[...]`-Felder und ein `bemerkungen`-Feld — `app.py` parst diese Felder und baut die Nachricht automatisch zusammen.

6. Weiteres / Troubleshooting

- Wenn Live Server beim Start weiterhin die Dateiliste zeigt, öffne `templates/index.html` direkt mit Live Server oder starte die Flask‑App.
- Prüfe, ob `DISCORD_WEBHOOK_URL` korrekt ist. Fehler beim Senden werden als Flashes im UI angezeigt.
- Für produktive Nutzung: Authentifizierung, Validierung, sichere Speicherung und HTTPS vorsehen.

Logo oben rechts

Lege das BF‑München‑Logo als PNG in das Verzeichnis `static` mit dem Dateinamen `bf_muenchen.png`. Die Template referenziert dieses Bild als `/static/bf_muenchen.png` und zeigt es oben rechts im Header an.

Beispiel (Projektstruktur):

```
d:\Atemschutzüberwachung
├─ static
│  └─ bf_muenchen.png   <-- hier Datei ablegen
├─ templates
│  └─ index.html
├─ app.py
```

s